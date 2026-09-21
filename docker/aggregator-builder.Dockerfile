# Reproducible builder for the ZiSK aggregator guest ELF.
#
# The aggregator programVK that ends up pinned on L1 and in the server's
# compiled ZiSK release manifest is the ROM merkle root
# of this ELF, so a given source revision must map to exactly one binary.
# Everything that influences the build is pinned here: the base image, the
# cargo-zisk release (which fixes the ZiSK Rust toolchain it installs), the
# committed guest-aggregator/Cargo.lock, and a fixed /build source path so
# no host paths leak into panic messages.
#
# Build (from the repo root; see build-aggregator.sh for the wrapper):
#   docker build -f docker/aggregator-builder.Dockerfile -o out .
#   sha256sum out/zksync-os-zisk-guest-aggregator

FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates xz-utils \
        build-essential git pkg-config libssl-dev \
        openmpi-bin libopenmpi-dev libsodium23 libgmp10 libomp5-18 \
        clang libclang-dev llvm-18 \
    && rm -rf /var/lib/apt/lists/*

# rustup provides the `cargo`/`rustc` proxies and the `toolchain link` that
# `cargo-zisk toolchain install` performs. No host toolchain is needed: the
# zisk-4.x toolchain tarball ships its own cargo next to its rustc, and
# `cargo-zisk build` runs that one (`cargo +zisk build`).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
        --default-toolchain none --profile minimal
ENV PATH=/root/.cargo/bin:/root/.zisk/bin:$PATH

# cargo-zisk from the pinned release. The `toolchain install` command fetches
# the ZiSK Rust toolchain, which supplies the riscv64ima-zisk-zkvm-elf target
# and its ziskos link script. That script defines _global_pointer,
# _init_stack_top, _kernel_heap_bottom and _kernel_heap_top, so the guest
# needs it to link.
#
# By default `toolchain install` picks the highest `zisk-4.x.y` tag, and that
# reference floats. A newer toolchain release can drop the link script from
# the target, so the guest fails to link and the recorded ELF stops
# reproducing. Pin the toolchain to the release that matches cargo-zisk
# 1.3.0-alpha (zisk-4.0.0: rustc 1.94.0-dev, LLVM 21.1.8). Download the exact
# artifact, verify its sha256, and hand it to `toolchain install` through
# ZISK_TOOLCHAIN_SOURCE_DIR. cargo-zisk then installs from the local file and
# makes no network fetch, so the toolchain no longer floats.
#
# The cargo-zisk tarball below is the v${ZISK_VERSION} GitHub release asset;
# `cargo-zisk build` only orchestrates `cargo +zisk build`, so the CPU build
# of the tarball is all this image needs from it.
ARG ZISK_VERSION=1.3.0-alpha
ARG ZISK_TOOLCHAIN_TAG=zisk-4.0.0
ARG ZISK_TOOLCHAIN_SHA256=c4c44b5612dd025f630c2f984ae5f8a862b885c4b14bfc57c980eb8073b8cf62
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
    && cargo +zisk --version && rustc +zisk --version

WORKDIR /build
COPY guest-aggregator /build/guest-aggregator

# LLVM may vary private symbol suffixes between identical builds. Strip
# non-loaded symbols so they cannot change the published ELF hash.
RUN cd /build/guest-aggregator \
    && cargo-zisk build --release \
    && ELF="$(find target -type f -name zksync-os-zisk-guest-aggregator -path '*/release/*' | head -1)" \
    && test -n "$ELF" \
    && llvm-strip-18 --strip-all "$ELF" \
    && cp "$ELF" /build/zksync-os-zisk-guest-aggregator \
    && sha256sum /build/zksync-os-zisk-guest-aggregator

FROM scratch AS export
COPY --from=builder /build/zksync-os-zisk-guest-aggregator /zksync-os-zisk-guest-aggregator
