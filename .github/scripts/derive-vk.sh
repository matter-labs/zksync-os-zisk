#!/usr/bin/env bash
set -euo pipefail

# Derive the programVK (ROM merkle root) of a guest ELF with
# `cargo-zisk program-setup`, reading the value from the .verkey.bin file the
# setup writes (32 bytes: four u64 limbs, little-endian each) rather than
# parsing log output. The canonical serialization is the four limbs big-endian,
# concatenated in order — identical to the prover daemon's public-values prefix
# and the server's `prover_api.zisk_vks[].program_vk` expectation.
#
# Usage: derive-vk.sh <elf> <outdir>
# Writes into <outdir>: program-setup.log, vk.hex (0x… on one line),
# vk.limbs (four decimal u64 limbs on one line, comma-separated).

elf=$1
outdir=$2
mkdir -p "$outdir"

cargo-zisk program-setup -e "$elf" -k "$HOME/.zisk/provingKey" -o "$outdir" \
    2>&1 | tee "$outdir/program-setup.log"

shopt -s nullglob
verkeys=("$outdir"/*.verkey.bin)
if [[ ${#verkeys[@]} -ne 1 ]]; then
    echo "ERROR: expected exactly one .verkey.bin in $outdir, found ${#verkeys[@]}" >&2
    exit 1
fi

python3 - "${verkeys[0]}" "$outdir" <<'EOF'
import struct
import sys

raw = open(sys.argv[1], "rb").read()
assert len(raw) == 32, f"verkey file holds {len(raw)} bytes, expected 32"
limbs = struct.unpack("<4Q", raw)
hexval = "0x" + b"".join(l.to_bytes(8, "big") for l in limbs).hex()
open(sys.argv[2] + "/vk.hex", "w").write(hexval + "\n")
open(sys.argv[2] + "/vk.limbs", "w").write(", ".join(str(l) for l in limbs) + "\n")
print(f"programVK: {hexval}")
print(f"limbs: {limbs}")
EOF
