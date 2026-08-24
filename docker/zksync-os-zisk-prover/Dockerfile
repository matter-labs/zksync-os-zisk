# Production image for the ZiSK prover daemon: the prover-service binary, the
# two hash-verified guest ELFs, and the pinned ZiSK GPU toolchain on a CUDA
# runtime base. The proving keys are NOT baked in (the STARK + PLONK keys are
# ~26-40 GB); they arrive at runtime via ziskup or a mounted volume — see
# README.md next to this file.
#
# Build from the repo root, AFTER the reproducible guest builds have
# populated out/ (stage-build.yaml runs them; they verify the ELF hashes):
#   ./build-guest.sh && ./build-aggregator.sh
#   docker build -f docker/zksync-os-zisk-prover/Dockerfile -t zksync-os-zisk-prover .

FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

# sccache plumbing; all empty (sccache off) unless the runner has GCS credentials
ARG SCCACHE_GCS_BUCKET
ARG SCCACHE_GCS_SERVICE_ACCOUNT
ARG SCCACHE_GCS_RW_MODE
ARG RUSTC_WRAPPER

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates build-essential pkg-config libssl-dev sccache && \
    rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y

WORKDIR /usr/src/zksync-os-zisk

# The prover's only path dependency is the aggregator crate (host build).
COPY guest-aggregator/ guest-aggregator/
COPY prover/ prover/

RUN cargo build --release --locked --manifest-path prover/Cargo.toml \
        --bin zksync-os-zisk-prover-service

# Runtime: cargo-zisk (GPU build) needs the CUDA runtime; 24.04 matches the builder's glibc.
FROM nvidia/cuda:12.9.1-runtime-ubuntu24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG ZISK_VERSION=0.18.0

# build-essential + libgmp-dev: cargo-zisk program-setup assembles and links at runtime (-lgmp/-lgmpxx).
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates xz-utils build-essential libgmp-dev \
        openmpi-bin libopenmpi-dev libsodium23 libgmp10 libomp5-18 && \
    rm -rf /var/lib/apt/lists/*

# Pinned ZiSK GPU toolchain; --nokey keeps the multi-GB proving keys out of the image, ziskup stays installed for runtime key setup.
RUN curl -fsSL "https://raw.githubusercontent.com/0xPolygonHermez/zisk/v${ZISK_VERSION}/ziskup/ziskup" \
        -o /usr/local/bin/ziskup && \
    chmod +x /usr/local/bin/ziskup && \
    ziskup -v "${ZISK_VERSION}" --system --prefix /opt/zisk --gpu --nokey -y

ENV ZISK_HOME=/opt/zisk \
    ZISK_VERSION=${ZISK_VERSION} \
    PATH=/opt/zisk/bin:$PATH

# Guest ELFs from the reproducible builds, re-verified against the recorded hashes so a stale out/ can never ship.
COPY out/zksync-os-zisk-guest out/zksync-os-zisk-guest-aggregator /app/elf/
COPY guest/GUEST_ELF_SHA256 /app/elf/zksync-os-zisk-guest.sha256
COPY guest-aggregator/GUEST_ELF_SHA256 /app/elf/zksync-os-zisk-guest-aggregator.sha256
RUN cd /app/elf && \
    echo "$(cut -d' ' -f1 < zksync-os-zisk-guest.sha256)  zksync-os-zisk-guest" | sha256sum -c - && \
    echo "$(cut -d' ' -f1 < zksync-os-zisk-guest-aggregator.sha256)  zksync-os-zisk-guest-aggregator" | sha256sum -c -

COPY --from=builder /usr/src/zksync-os-zisk/prover/target/release/zksync-os-zisk-prover-service /usr/local/bin/zksync-os-zisk-prover-service
COPY docker/zksync-os-zisk-prover/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
