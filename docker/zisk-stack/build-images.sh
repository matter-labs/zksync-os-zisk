#!/usr/bin/env bash
# Build, and optionally push, the ZiSK stack image from the repo root.
#
#   docker/zisk-stack/build-images.sh --prover-from-docker             # dev build
#   docker/zisk-stack/build-images.sh --prover-from-release 0.0.6      # released binary + ELFs
#   docker/zisk-stack/build-images.sh --prover-bin PATH --skip-guest-build
#
# Options:
#   --registry PREFIX    image name prefix (default: local)
#   --tag TAG            image tag (default: dev)
#   --push               push to the registry instead of loading locally
#   --skip-guest-build   reuse out/ ELFs instead of running the reproducible builds
#   --repo OWNER/NAME    GitHub repo for --prover-from-release (default: matter-labs/zksync-os-zisk)
#   --prover-from-docker       build the daemon in a container from this checkout
#   --prover-from-release TAG  use the released host-tools tarball and guest ELFs
#                              (SHA256SUMS-verified), so the image carries the exact
#                              binaries the release manifest pins
#   --prover-bin PATH          use a prebuilt linux/amd64 daemon binary
#
# The ZiSK binaries come from the pinned tarball. The image also copies
# out/zksync-os-zisk-guest, out/zksync-os-zisk-guest-aggregator and
# out/zksync-os-zisk-prover-service; the Dockerfile re-verifies the ELFs
# against the recorded GUEST_ELF_SHA256 pins.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOCKERFILE="$ROOT/docker/zisk-stack/Dockerfile"
PLATFORM=linux/amd64
IMAGE_NAME=zksync-os-zisk-prover
REGISTRY=local
TAG=dev
PUSH=0
SKIP_GUEST_BUILD=0
PROVER_SOURCE=""
PROVER_BIN=""
RELEASE_TAG=""
REPO=matter-labs/zksync-os-zisk

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "ERROR: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --registry) REGISTRY="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --push) PUSH=1; shift ;;
        --skip-guest-build) SKIP_GUEST_BUILD=1; shift ;;
        --repo) REPO="$2"; shift 2 ;;
        --prover-from-docker) PROVER_SOURCE=docker; shift ;;
        --prover-from-release) PROVER_SOURCE=release; RELEASE_TAG="$2"; shift 2 ;;
        --prover-bin) PROVER_SOURCE=bin; PROVER_BIN="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

sha256_check() {
    # $1 = checksum file (sha256sum format) restricted to the files present.
    if command -v sha256sum >/dev/null; then
        sha256sum -c --strict "$1"
    else
        shasum -a 256 -c --strict "$1"
    fi
}

cd "$ROOT"
mkdir -p out

case "$PROVER_SOURCE" in
    release)
        command -v gh >/dev/null || die "--prover-from-release needs the gh CLI"
        dist="$(mktemp -d)"
        host_tools="zksync-os-zisk-prover-${RELEASE_TAG}-x86_64-unknown-linux-gnu.tar.gz"
        guest_elfs="zksync-os-zisk-guest-elfs-${RELEASE_TAG}.tar.gz"
        echo "=== downloading release ${RELEASE_TAG} assets from ${REPO}"
        gh release download "$RELEASE_TAG" -R "$REPO" -D "$dist" \
            -p SHA256SUMS -p "$host_tools" -p "$guest_elfs"
        (cd "$dist" && grep -E " (${host_tools}|${guest_elfs})\$" SHA256SUMS > SHA256SUMS.selected \
            && sha256_check SHA256SUMS.selected)
        tar -xzf "${dist}/${host_tools}" -C "$dist" zksync-os-zisk-prover-service
        cp "${dist}/zksync-os-zisk-prover-service" out/zksync-os-zisk-prover-service
        tar -xzf "${dist}/${guest_elfs}" -C out zksync-os-zisk-guest zksync-os-zisk-guest-aggregator
        rm -rf "$dist"
        # Released ELFs are the reproducible builds already; the Dockerfile
        # still checks them against the pins in this checkout.
        SKIP_GUEST_BUILD=1
        ;;
    docker)
        echo "=== building the daemon in a container (target prover-export)"
        docker buildx build --platform "$PLATFORM" -f "$DOCKERFILE" \
            --target prover-export -o out .
        ;;
    bin)
        [[ -f "$PROVER_BIN" ]] || die "no such file: $PROVER_BIN"
        cp "$PROVER_BIN" out/zksync-os-zisk-prover-service
        ;;
    "")
        die "the daemon binary needs --prover-from-docker, --prover-from-release TAG or --prover-bin PATH"
        ;;
esac
if (( ! SKIP_GUEST_BUILD )); then
    ./build-guest.sh
    ./build-aggregator.sh
fi
for f in out/zksync-os-zisk-guest out/zksync-os-zisk-guest-aggregator out/zksync-os-zisk-prover-service; do
    [[ -f "$f" ]] || die "missing $f"
done

image="${REGISTRY}/${IMAGE_NAME}:${TAG}"
echo "=== building ${image} (target stack, ${PLATFORM})"
args=(buildx build --platform "$PLATFORM" -f "$DOCKERFILE" --target stack -t "$image")
if (( PUSH )); then args+=(--push); else args+=(--load); fi
docker "${args[@]}" .
echo "done"
