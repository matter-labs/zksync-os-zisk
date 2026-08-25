#!/usr/bin/env bash
set -euo pipefail

# Reproducible aggregator guest build: compiles the ELF inside the pinned
# container (docker/aggregator-builder.Dockerfile) and checks the result
# against the recorded hash in guest-aggregator/GUEST_ELF_SHA256.
#
# Usage:
#   ./build-aggregator.sh            # build + verify against the recorded hash
#   ./build-aggregator.sh --record   # build + (re)record the hash — do this
#                                    # when the aggregator or its inputs
#                                    # intentionally change, and commit the
#                                    # updated GUEST_ELF_SHA256.
#
# The ELF lands in out/zksync-os-zisk-guest-aggregator. Its programVK (the
# value in the server's compiled ZiSK release manifest and the L1
# range-verifier pin) is derived on a prover box with:
#   cargo-zisk program-setup -e out/zksync-os-zisk-guest-aggregator -k ~/.zisk/provingKey
# — deterministic given the ELF and the pinned cargo-zisk version.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HASH_FILE="$SCRIPT_DIR/guest-aggregator/GUEST_ELF_SHA256"
OUT_DIR="$SCRIPT_DIR/out"
RECORD=0
[[ "${1:-}" == "--record" ]] && RECORD=1

echo "=== Building ZiSK aggregator guest in pinned container ==="
DOCKER_BUILDKIT=1 docker build \
    -f "$SCRIPT_DIR/docker/aggregator-builder.Dockerfile" \
    --target export -o "$OUT_DIR" "$SCRIPT_DIR"

ELF="$OUT_DIR/zksync-os-zisk-guest-aggregator"
ACTUAL="$(sha256sum "$ELF" | cut -d' ' -f1)"
echo "ELF: $ELF"
echo "sha256: $ACTUAL"

if [[ "$RECORD" == 1 ]]; then
    echo "$ACTUAL" > "$HASH_FILE"
    echo "Recorded to $HASH_FILE — commit this file."
    exit 0
fi

if [[ ! -f "$HASH_FILE" ]]; then
    echo "ERROR: no recorded hash at $HASH_FILE — run with --record first." >&2
    exit 1
fi
EXPECTED="$(cut -d' ' -f1 < "$HASH_FILE")"
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    echo "ERROR: aggregator ELF hash mismatch" >&2
    echo "  expected: $EXPECTED" >&2
    echo "  actual:   $ACTUAL" >&2
    echo "The build is not reproducing the recorded binary. If the change is" >&2
    echo "intentional, re-run with --record and commit the new hash (the" >&2
    echo "aggregator programVK rotates with it)." >&2
    exit 1
fi
echo "OK: matches recorded hash."
