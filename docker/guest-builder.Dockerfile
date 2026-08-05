# Reproducible builder for the ZiSK guest ELF.
#
# The programVK that ends up pinned on L1 (and in the server's
# `prover_api.zisk_vks` tripwire) is the ROM merkle root of this ELF, so a
# given source revision must map to exactly one binary.
# Everything that influences the build is pinned here: the base image, the
# cargo-zisk release (which fixes the ZiSK Rust toolchain it installs), the
# committed guest/Cargo.lock, and a fixed /build source path so no host
# paths leak into panic messages.
#
# Build (from the repo root; see build-guest.sh for the one-command wrapper):
#   docker build -f docker/guest-builder.Dockerfile -o out .
#   sha256sum out/zksync-os-zisk-guest

FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates xz-utils \
        build-essential git pkg-config libssl-dev \
        openmpi-bin libopenmpi-dev libsodium23 libgmp10 libomp5-18 \
        clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# The `zisk` toolchain installed below provides rustc but no cargo. Rustup's
# cargo fallback only applies to toolchains named stable/beta/nightly, so a
# pinned cargo is copied into the zisk toolchain directly (see below).
# Codegen is entirely the zisk rustc's — cargo only orchestrates — but pin it
# anyway so nothing about the build floats with the image build date.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
        --default-toolchain 1.87.0 --profile minimal
ENV PATH=/root/.cargo/bin:/root/.zisk/bin:$PATH

# cargo-zisk from the pinned release. The `toolchain install` command fetches
# the ZiSK Rust toolchain, which supplies the riscv64ima-zisk-zkvm-elf target
# and its ziskos link script. That script defines _global_pointer,
# _init_stack_top, _kernel_heap_bottom and _kernel_heap_top, so the guest
# needs it to link.
#
# By default `toolchain install` downloads the "latest" toolchain release, and
# that reference floats. A newer toolchain release drops the link script from
# the target, so the guest fails to link and the recorded ELF stops
# reproducing. Pin the toolchain to the release that matches cargo-zisk
# 0.18.0 (the release that was current at the 2026-05-15 build). Download the
# exact artifact, verify its sha256, and hand it to `toolchain install` through
# ZISK_TOOLCHAIN_SOURCE_DIR. cargo-zisk then installs from the local file and
# makes no network fetch, so the toolchain no longer floats.
ARG ZISK_VERSION=0.18.0
ARG ZISK_TOOLCHAIN_TAG=zisk-0.5.1
ARG ZISK_TOOLCHAIN_SHA256=b2eb5e86568ec29e68a813683edb54616478d473b3e179c7fe880dbf764c11c5
RUN curl -fsSL -o /tmp/cargo_zisk.tar.gz \
        https://github.com/0xPolygonHermez/zisk/releases/download/v${ZISK_VERSION}/cargo_zisk_linux_amd64.tar.gz \
    && mkdir -p /root/.zisk \
    && tar -xzf /tmp/cargo_zisk.tar.gz -C /root/.zisk \
    && mv /root/.zisk/bin/cargo-zisk-cpu /root/.zisk/bin/cargo-zisk \
    && rm /tmp/cargo_zisk.tar.gz \
    && cargo-zisk --version \
    && mkdir -p /tmp/zisk-toolchain \
    && curl -fsSL -o /tmp/zisk-toolchain/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz \
        https://github.com/0xPolygonHermez/rust/releases/download/${ZISK_TOOLCHAIN_TAG}/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz \
    && echo "${ZISK_TOOLCHAIN_SHA256}  /tmp/zisk-toolchain/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz" | sha256sum -c - \
    && ZISK_TOOLCHAIN_SOURCE_DIR=/tmp/zisk-toolchain cargo-zisk toolchain install \
    && rm -rf /tmp/zisk-toolchain \
    && cp /root/.rustup/toolchains/1.87.0-x86_64-unknown-linux-gnu/bin/cargo \
          /root/.rustup/toolchains/zisk/bin/cargo

WORKDIR /build
COPY lib /build/lib
COPY guest /build/guest

RUN cd /build/guest \
    && cargo-zisk build --release \
    && ELF="$(find target -type f -name zksync-os-zisk-guest -path '*/release/*' | head -1)" \
    && test -n "$ELF" \
    && nm -C "$ELF" | grep -q 'ziskos::alloc::embedded_dlmalloc::DLMALLOC' \
    && cp "$ELF" /build/zksync-os-zisk-guest \
    && sha256sum /build/zksync-os-zisk-guest

FROM scratch AS export
COPY --from=builder /build/zksync-os-zisk-guest /zksync-os-zisk-guest
