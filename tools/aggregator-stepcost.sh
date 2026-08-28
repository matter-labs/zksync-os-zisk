#!/usr/bin/env bash
# Aggregator-guest step-cost measurement.
#
# Builds the aggregator guest ELF and the host-side input assembler,
# assembles a framed guest input from per-batch vadcop_final proofs, and
# runs ONE memory-capped ziskemu per configuration to extract executed
# steps. Runs the workload twice — with N proofs and with 2N proofs — and
# reports the marginal cost per verified proof:
#
#   steps/proof = (steps(2N) - steps(N)) / N
#
# which is the number that gates the design (expect ~10^6–10^7
# steps/proof; a 10-batch range must fit one execution, i.e. stay far
# below the 2^36-step ceiling with the recursion stages on top).
#
# REAL NUMBERS NEED REAL PROOFS. Pass per-batch proofs produced by
# `cargo-zisk prove` WITHOUT `--plonk` (a Vadcop-body proof file; the
# --plonk output has discarded the vadcop_final proof), or raw
# get_proof_bytes() streams. Minting them needs the ~50 GB proving keys —
# see gpu-box-archive/scripts/aggregator-session.md for the box runbook.
#
# Without arguments the script runs the SYNTHETIC plumbing check:
# structurally exact but cryptographically invalid streams. The guest must
# parse every frame and die INSIDE proof verification ("proof 0:
# verification failed") — that proves the input framing, parsing, VK
# checks and the verifier entry are all wired, and only real specimens are
# missing. Any other panic is a plumbing bug.
#
# Note: a guest panic does NOT halt
# ziskemu — after printing the panic the emulator keeps stepping to its
# ceiling (default 2^36-1) and exits `Error during emulation:
# EmulationNoCompleted` (~8 min wall per run on this box). An invalid
# proof therefore costs the FULL step budget, not a fast failure. Design
# consequence: the aggregation stage's cost gate
# must budget WORST-CASE verification cost for invalid submissions — a
# malicious/garbage proof burns prover time, never soundness (a
# non-completing execution yields no proof). This script bounds its own
# runs with `ziskemu -n` for the same reason.
#
# Usage:
#   tools/aggregator-stepcost.sh                       # synthetic plumbing check
#   tools/aggregator-stepcost.sh proof1.bin proof2.bin # real measurement
#
# Environment (defaults for this workstation):
#   ZISK_BIN_DIR        cargo-zisk-cpu + ziskemu location (~/.zisk-1.2.0-alpha/bin)
#   STEPCOST_OUT        work/output directory
#   SYNTHETIC_N         N for the synthetic mode (default 2)
#   STEPCOST_MAX_STEPS  ziskemu step cap (default 4e9: ~64x the estimated
#                       10-proof range cost, bounds a bad input to ~30 s)
#
# Memory discipline: ziskemu peaks at ~7 GB RSS; every run is wrapped in
# `ulimit -v 10485760` (10 GiB address-space cap) and runs strictly one at
# a time.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
ZISK_BIN_DIR="${ZISK_BIN_DIR:-$HOME/.zisk-1.2.0-alpha/bin}"
ZISKEMU="$ZISK_BIN_DIR/ziskemu"
CARGO_ZISK="$ZISK_BIN_DIR/cargo-zisk-cpu"
STEPCOST_OUT="${STEPCOST_OUT:-$HOME/multiprover/aggregator-stepcost-out}"
SYNTHETIC_N="${SYNTHETIC_N:-2}"
MAX_STEPS="${STEPCOST_MAX_STEPS:-4000000000}"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-$HOME/.local/zisk-libs/usr/lib/x86_64-linux-gnu:$HOME/.local/zisk-libs/usr/lib/x86_64-linux-gnu/openmpi/lib}"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0

mkdir -p "$STEPCOST_OUT"

echo "=== building aggregator guest ELF (cargo-zisk-cpu) ==="
(cd "$REPO_DIR/guest-aggregator" && "$CARGO_ZISK" build --release) || exit 1
ELF="$REPO_DIR/guest-aggregator/target/elf/riscv64ima-zisk-zkvm-elf/release/zksync-os-zisk-guest-aggregator"
[ -f "$ELF" ] || { echo "missing ELF: $ELF"; exit 1; }

echo "=== building input assembler (aggregator_input) ==="
(cd "$REPO_DIR/prover" && cargo build --release --bin aggregator_input) || exit 1
ASSEMBLER="$REPO_DIR/prover/target/release/aggregator_input"
[ -x "$ASSEMBLER" ] || { echo "missing assembler: $ASSEMBLER"; exit 1; }

# emu_one <input.bin> <log-file>: ONE memory- and step-capped ziskemu run.
# Prints "steps=<n>" on success, "panic:<message>" on guest panic (a panic
# never completes the emulation (see the note above), so the step cap
# is what bounds it), "nocomplete:..." if the cap was hit without a panic.
emu_one() {
    local input="$1" log="$2" rc out
    out=$( (ulimit -v 10485760; nice -n 10 "$ZISKEMU" -e "$ELF" -i "$input" -n "$MAX_STEPS" -m) 2>&1 )
    rc=$?
    printf '%s\n' "$out" > "$log"
    if grep -qi "panicked\|panic at" <<< "$out"; then
        # The panic message is on the line AFTER "panicked at <loc>".
        echo "panic:$(grep -im1 -A1 "panicked" <<< "$out" | tr '\n\t' '  ' | cut -c1-220)"
    elif grep -q "EmulationNoCompleted" <<< "$out"; then
        echo "nocomplete:hit the $MAX_STEPS-step cap before finishing (raise STEPCOST_MAX_STEPS?)"
    elif [ $rc -ne 0 ]; then
        echo "error:ziskemu exited $rc: $(tr '\n\t' '  ' <<< "$out" | cut -c1-220)"
    else
        echo "$(grep -oE "steps=[0-9]+" <<< "$out" | head -1)"
    fi
}

if [ $# -ge 1 ]; then
    MODE="real"
    N=$#
    echo "=== assembling inputs from $N real proof file(s) ==="
    "$ASSEMBLER" -o "$STEPCOST_OUT/input_n.bin" "$@" || exit 1
    # 2N = the same list twice (verifying one proof twice costs the same
    # as verifying two distinct ones; only the marginal cost matters).
    "$ASSEMBLER" -o "$STEPCOST_OUT/input_2n.bin" "$@" "$@" || exit 1
else
    MODE="synthetic"
    N="$SYNTHETIC_N"
    echo "=== no proof files given: SYNTHETIC plumbing check (N=$N) ==="
    "$ASSEMBLER" -o "$STEPCOST_OUT/input_n.bin" --synthetic "$N" || exit 1
    "$ASSEMBLER" -o "$STEPCOST_OUT/input_2n.bin" --synthetic "$((2 * N))" || exit 1
fi

echo "=== ziskemu run 1/2: $N proof(s) ==="
R1=$(emu_one "$STEPCOST_OUT/input_n.bin" "$STEPCOST_OUT/emu_n.log")
echo "    $R1"
echo "=== ziskemu run 2/2: $((2 * N)) proof(s) ==="
R2=$(emu_one "$STEPCOST_OUT/input_2n.bin" "$STEPCOST_OUT/emu_2n.log")
echo "    $R2"

echo
echo "=== RESULT ==="
if [ "$MODE" = "synthetic" ]; then
    if grep -q "verification failed" <<< "$R1$R2"; then
        echo "plumbing OK, real numbers need real vadcop_final specimens:"
        echo "  the guest parsed the count frame and every proof frame (framing,"
        echo "  section offsets, VK extraction all valid) and failed only INSIDE"
        echo "  verify_zisk_proof — the expected outcome for synthetic streams,"
        echo "  which are cryptographically invalid by construction."
        echo "  Expect 'EmulationNoCompleted' in the logs alongside the panic:"
        echo "  a panicking guest never completes, ziskemu steps on to the cap"
        echo "  (see the note in this script's header; invalid input costs"
        echo "  the full step budget, a prover-time cost, never soundness)."
        echo "  Step numbers require real vadcop_final proofs: mint them per"
        echo "  gpu-box-archive/scripts/aggregator-session.md and re-run this"
        echo "  script with the proof files as arguments."
        exit 0
    else
        echo "PLUMBING BROKEN: expected a panic inside verification, got:"
        echo "  run N : $R1"
        echo "  run 2N: $R2"
        echo "  (a parse-stage panic means assembler and guest disagree on the"
        echo "   frame layout; see $STEPCOST_OUT/emu_*.log)"
        exit 1
    fi
fi

S1=$(grep -oE "[0-9]+" <<< "$R1" | head -1)
S2=$(grep -oE "[0-9]+" <<< "$R2" | head -1)
if [[ "$R1" != steps=* || "$R2" != steps=* ]]; then
    echo "FAILED: at least one run did not complete cleanly:"
    echo "  run N : $R1"
    echo "  run 2N: $R2"
    echo "  logs: $STEPCOST_OUT/emu_n.log, $STEPCOST_OUT/emu_2n.log"
    exit 1
fi
MARGINAL=$(( (S2 - S1) / N ))
echo "steps($N proofs)        = $S1"
echo "steps($((2 * N)) proofs)        = $S2"
echo "marginal steps/proof    = $MARGINAL"
echo "fixed overhead (approx) = $((S1 - MARGINAL * N))"
echo
echo "gate: expected ~10^6–10^7 steps/proof; a 10-batch range"
echo "needs 10 * marginal + overhead well below the 2^36-step ceiling."
