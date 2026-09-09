# syntax=docker/dockerfile:1.7
# One image for the whole ZiSK proving stack of ZKsync OS. It holds every
# binary the three processes need; the process is chosen by the command:
#
#   zisk-coordinator --config /etc/zisk/coordinator.toml   CPU. Job queue and client API.
#   zisk-worker --config /etc/zisk/worker.toml ...         GPU. Holds the proving keys
#                                                          resident, proves.
#   zksync-os-zisk-prover-service ...                      CPU. Polls the sequencer and
#                                                          drives the coordinator through
#                                                          `cargo-zisk remote`.
#   zisk-prepare-keys                                      One-shot. Fetches, verifies and
#                                                          installs the proving keys into
#                                                          the worker's key volume.
#
# One tag therefore pins coordinator, worker and daemon together. Every ZiSK
# binary comes from the same pinned release tarball, verified by sha256 before
# extraction; nothing ZiSK is compiled here. The daemon binary and the two
# guest ELFs come from out/ in the build context: the reproducible guest
# builds plus either the `prover-export` stage below or a release's assets
# (see build-images.sh). The ELFs are re-verified against the recorded pins.
#
# The tarball is x86_64 only, so the image is linux/amd64. The GPU binaries
# link only the driver's libcuda.so.1, which the NVIDIA container toolkit
# mounts at run time, so the base is plain Ubuntu. The proving keys are NOT
# in the image (26 GB compressed); see README.md next to this file.

ARG ZISK_VERSION=1.2.0-alpha
ARG ZISK_TARBALL_SHA256=e3605dafb5fcdb2fa8271ea945334694f42704737f31ef0bdf93d663f2b14866
ARG UBUNTU_TAG=24.04

# ---------------------------------------------------------------------------
# The pinned ZiSK toolchain tarball, sha256-verified and unpacked once.
FROM ubuntu:${UBUNTU_TAG} AS toolchain
ARG ZISK_VERSION
ARG ZISK_TARBALL_SHA256
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL --retry 5 -o /tmp/cargo_zisk.tar.gz \
        "https://github.com/0xPolygonHermez/zisk/releases/download/v${ZISK_VERSION}/cargo_zisk_linux_amd64.tar.gz" \
    && echo "${ZISK_TARBALL_SHA256}  /tmp/cargo_zisk.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/zisk-dist \
    && tar --no-same-owner -xzf /tmp/cargo_zisk.tar.gz -C /opt/zisk-dist \
    && rm /tmp/cargo_zisk.tar.gz \
    && ls -la /opt/zisk-dist/bin

# ---------------------------------------------------------------------------
# Optional helper: build the daemon from this checkout inside a container and
# export the binary into out/, for developer builds and the CI dev images. A
# release build skips this and puts the released binary in out/ instead.
FROM rust:1-bookworm AS prover-build
WORKDIR /src
# The prover's only path dependency is the aggregator crate (host build).
COPY guest-aggregator/ guest-aggregator/
COPY prover/ prover/
RUN cargo build --release --locked --manifest-path prover/Cargo.toml \
        --bin zksync-os-zisk-prover-service

FROM scratch AS prover-export
COPY --from=prover-build /src/prover/target/release/zksync-os-zisk-prover-service /zksync-os-zisk-prover-service

# ---------------------------------------------------------------------------
FROM ubuntu:${UBUNTU_TAG} AS stack
ARG ZISK_VERSION
ARG DEBIAN_FRONTEND=noninteractive
# Runtime libraries the tarball's binaries link (gmp, gomp and omp, OpenMPI,
# sodium), curl for health checks and the key download, and the toolchain the
# ASM emulator path assembles a per-program emulator with at setup time
# (make, as, ld, gcc, -lgmp -lgmpxx -lstdc++). A worker started with
# --emulator never uses that toolchain; having it here makes the emulator
# choice a runtime flag instead of an image variant.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
        libgmp10 libgomp1 libomp5-18 libopenmpi3t64 libsodium23 \
        build-essential libgmp-dev \
    && rm -rf /var/lib/apt/lists/*
# Same uid/gid as ZiSK's own images.
RUN groupadd --system --gid 999 zisk \
    && useradd --system --uid 998 --gid zisk --no-create-home \
               --shell /usr/sbin/nologin --home-dir /opt/zisk zisk \
    && mkdir -p /opt/zisk/bin /opt/zisk/keys /var/cache/zisk /var/lib/zisk-prover /etc/zisk \
    && chown -R zisk:zisk /opt/zisk /var/cache/zisk /var/lib/zisk-prover

# ZiSK binaries. cargo-zisk is the CPU build: only its `remote` subcommands
# run here. cargo-zisk-dev is the GPU build: zisk-prepare-keys runs its
# check-setup to generate the constant trees.
COPY --from=toolchain --chown=root:root --chmod=0755 \
     /opt/zisk-dist/bin/zisk-coordinator /opt/zisk/bin/zisk-coordinator
COPY --from=toolchain --chown=root:root --chmod=0755 \
     /opt/zisk-dist/bin/zisk-worker-gpu /opt/zisk/bin/zisk-worker
COPY --from=toolchain --chown=root:root --chmod=0755 \
     /opt/zisk-dist/bin/cargo-zisk-cpu /opt/zisk/bin/cargo-zisk
COPY --from=toolchain --chown=root:root --chmod=0755 \
     /opt/zisk-dist/bin/cargo-zisk-dev-gpu /opt/zisk/bin/cargo-zisk-dev
COPY --from=toolchain --chown=root:root \
     /opt/zisk-dist/bin/libziskc.a /opt/zisk-dist/bin/libziskclib.a /opt/zisk/bin/
# emulator-asm and lib-c sources the ASM setup builds against; the worker
# writes its build output next to them.
COPY --from=toolchain --chown=zisk:zisk /opt/zisk-dist/zisk /opt/zisk/zisk

# Configuration and the key preparation step.
COPY --chown=root:root docker/zisk-stack/coordinator.toml docker/zisk-stack/coordinator-core.toml \
     docker/zisk-stack/worker.toml /etc/zisk/
COPY --chown=root:root --chmod=0755 docker/zisk-stack/prepare-keys.sh /usr/local/bin/zisk-prepare-keys
COPY --chown=root:root docker/zisk-stack/keys.sha256 /opt/zisk/keys.sha256

# Guest ELFs from the reproducible builds, re-verified against the recorded
# hashes so a stale out/ can never ship, and the daemon.
COPY out/zksync-os-zisk-guest out/zksync-os-zisk-guest-aggregator /app/elf/
COPY guest/GUEST_ELF_SHA256 /app/elf/zksync-os-zisk-guest.sha256
COPY guest-aggregator/GUEST_ELF_SHA256 /app/elf/zksync-os-zisk-guest-aggregator.sha256
RUN cd /app/elf \
    && echo "$(cut -d' ' -f1 < zksync-os-zisk-guest.sha256)  zksync-os-zisk-guest" | sha256sum -c - \
    && echo "$(cut -d' ' -f1 < zksync-os-zisk-guest-aggregator.sha256)  zksync-os-zisk-guest-aggregator" | sha256sum -c -
COPY --chown=root:root --chmod=0755 out/zksync-os-zisk-prover-service /usr/local/bin/zksync-os-zisk-prover-service

# ZiSK path layout the binaries resolve through ZISK_HOME and ZISK_CACHE_DIR,
# and the NVIDIA container toolkit request for the GPU processes (harmless
# for the CPU ones).
ENV ZISK_HOME=/opt/zisk \
    ZISK_CACHE_DIR=/var/cache/zisk \
    ZISK_VERSION=${ZISK_VERSION} \
    PATH=/opt/zisk/bin:$PATH \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility
# coordinator API | coordinator cluster port | coordinator metrics | daemon metrics
EXPOSE 7000 50051 9090 3313
LABEL org.opencontainers.image.title="zksync-os-zisk-prover" \
      org.opencontainers.image.description="ZKsync OS ZiSK proving stack: coordinator, GPU worker, prover daemon and key preparation in one image; pick the process with the command" \
      org.opencontainers.image.source="https://github.com/matter-labs/zksync-os-zisk" \
      org.opencontainers.image.vendor="Matter Labs" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
USER zisk
WORKDIR /var/cache/zisk
# No ENTRYPOINT: compose and Helm select the process with the command. The
# default only documents that.
CMD ["zksync-os-zisk-prover-service", "--help"]
