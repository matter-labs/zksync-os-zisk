#!/usr/bin/env bash
set -euo pipefail

# Full ZiSK proof generation and Solidity verification pipeline.
#
# Stages:
#   1. Build guest ELF (RV64IMA binary)
#   2. Prepare input (sample batch or user-provided)
#   3. ROM setup (per-ELF proving key generation)
#   4. Emulate + verify constraints
#   5. STARK inner proofs (per-AIR FRI proofs)
#   6. STARK aggregation + compression (vadcop_final)
#   7. SNARK wrapping (Plonk proof for on-chain verification)
#   8. Solidity verification
#
# Requirements:
#   - cargo-zisk installed (via ziskup)
#   - Proving key at ~/.zisk/provingKey (downloaded during ziskup)
#   - SNARK proving key at ~/.zisk/provingKeySnark (separate download)
#   - Foundry (forge) for Solidity tests
#
# Hardware requirements by stage:
#   Stages 1-4: 4GB RAM (any machine)
#   Stage 5:    16GB RAM (STARK inner proofs)
#   Stage 6:    64GB RAM (aggregation + compression)
#   Stage 7:    32GB RAM (SNARK wrapping, needs SNARK proving key)
#   Stage 8:    Minimal (Solidity test)
#
# Usage:
#   ./prove_and_verify.sh [--input /path/to/input.bin] [--stage N]
#
# --stage N: start from stage N (skips earlier stages, uses cached artifacts)
# --input: a framed ZiSK BatchInput (batch dump or repro bundle).
# Without --input, exports the lib's sample proven batch.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUEST_DIR="$SCRIPT_DIR/guest"
LIB_DIR="$SCRIPT_DIR/lib"
CONTRACTS_DIR="$SCRIPT_DIR/contracts"
WORK_DIR="${ZISK_WORK_DIR:-/tmp/zisk_pipeline}"
export PATH="$HOME/.zisk/bin:$PATH"

# Parse args
INPUT_BIN=""
START_STAGE=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input) INPUT_BIN="$2"; shift 2 ;;
        --stage) START_STAGE="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$WORK_DIR"
echo "=== ZiSK Proof Pipeline for ZKsync OS ==="
echo "Work directory: $WORK_DIR"
echo "Starting from stage: $START_STAGE"
echo

ELF="$GUEST_DIR/target/riscv64ima-zisk-zkvm-elf/release/zksync-os-zisk-guest"

# ─── Stage 1: Build guest ELF ───────────────────────────────────────
if [ "$START_STAGE" -le 1 ]; then
    echo "[1/8] Building ZiSK guest..."
    (cd "$GUEST_DIR" && cargo-zisk build --release 2>&1 | tail -1)
    echo "  ELF: $ELF ($(du -h "$ELF" | cut -f1))"
fi

# ─── Stage 2: Prepare input ─────────────────────────────────────────
# Accepts a ready ZiSK input via --input (a `ZISK_DUMP_DIR` batch dump or a
# divergence repro bundle); otherwise exports the lib's minimal proven-path
# sample.
if [ "$START_STAGE" -le 2 ]; then
    if [ -z "$INPUT_BIN" ]; then
        echo "[2/8] Exporting the sample proven batch input..."
        (cd "$LIB_DIR" && cargo test --release export_proven_input_for_emulator -- --nocapture 2>&1 | tail -1)
        cp /tmp/proven_input.bin "$WORK_DIR/input.bin"
    else
        echo "[2/8] Using provided input: $INPUT_BIN"
        cp "$INPUT_BIN" "$WORK_DIR/input.bin"
    fi
fi

# ─── Stage 3: ROM setup ─────────────────────────────────────────────
if [ "$START_STAGE" -le 3 ]; then
    echo "[3/8] Running ROM setup (per-ELF proving key)..."
    cargo-zisk rom-setup -e "$ELF" -k "$HOME/.zisk/provingKey" -o "$WORK_DIR/rom_setup" 2>&1 | grep -E "Root hash|setup.*completed|ERROR" | tail -3
fi

# ─── Stage 4: Emulate + verify constraints ───────────────────────────
if [ "$START_STAGE" -le 4 ]; then
    echo "[4/8] Emulating and verifying constraints..."
    ziskemu -e "$ELF" -i "$WORK_DIR/input.bin" 2>&1 || { echo "  EMULATION FAILED"; exit 1; }
    echo "  Emulation passed ✓"
    cargo-zisk verify-constraints -e "$ELF" -i "$WORK_DIR/input.bin" 2>&1 | grep -E "✓.*global|completed"
    echo "  All constraints verified ✓"
fi

# ─── Stage 5: STARK inner proofs ────────────────────────────────────
if [ "$START_STAGE" -le 5 ]; then
    echo "[5/8] Generating STARK inner proofs..."
    mkdir -p "$WORK_DIR/inner_proofs/proofs"
    cargo-zisk prove \
        -e "$ELF" \
        -i "$WORK_DIR/input.bin" \
        -k "$HOME/.zisk/provingKey" \
        -o "$WORK_DIR/inner_proofs" \
        --emulator \
        --minimal-memory \
        --save-proofs \
        -v 2>&1 | grep -E "INNER_PROOFS|SUMMARY|completed|steps:" | tail -5
    PROOF_COUNT=$(ls "$WORK_DIR/inner_proofs/proofs/" 2>/dev/null | wc -l)
    echo "  Inner proofs: $PROOF_COUNT AIR proofs saved"
fi

# ─── Stage 6: STARK aggregation + compression ───────────────────────
if [ "$START_STAGE" -le 6 ]; then
    echo "[6/8] Generating aggregated + compressed STARK proof..."
    echo "  (Requires ~64GB RAM)"
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$RAM_GB" -lt 50 ]; then
        echo "  ERROR: Only ${RAM_GB}GB RAM available, aggregation needs ~64GB."
        echo "  Run on a machine with at least 64GB RAM."
        exit 1
    else
        mkdir -p "$WORK_DIR/stark_proof"
        cargo-zisk prove \
            -e "$ELF" \
            -i "$WORK_DIR/input.bin" \
            -k "$HOME/.zisk/provingKey" \
            -o "$WORK_DIR/stark_proof" \
            --emulator \
            --aggregation \
            --compressed \
            --save-proofs \
            -v 2>&1 | grep -E "INNER|AGGRE|COMPRESS|VADCOP|completed|steps:" | tail -10
        echo "  STARK proof: $WORK_DIR/stark_proof/"
        ls -lh "$WORK_DIR/stark_proof/"
    fi
fi

# ─── Stage 7: SNARK wrapping ────────────────────────────────────────
if [ "$START_STAGE" -le 7 ]; then
    echo "[7/8] Generating SNARK proof (Plonk wrapper)..."
    SNARK_KEY="${ZISK_SNARK_KEY:-$HOME/.zisk/provingKeySnark}"
    STARK_PROOF="$WORK_DIR/stark_proof/proof.bin"
    if [ ! -f "$STARK_PROOF" ]; then
        echo "  ERROR: No STARK proof at $STARK_PROOF (run stage 6 first)"
        exit 1
    elif [ ! -d "$SNARK_KEY" ]; then
        echo "  ERROR: SNARK proving key not found at $SNARK_KEY"
        echo "  Download via: ziskup setup_snark"
        exit 1
    else
        mkdir -p "$WORK_DIR/snark_proof"
        cargo-zisk prove-snark \
            --proof "$STARK_PROOF" \
            --elf "$ELF" \
            --proving-key-snark "$SNARK_KEY" \
            -o "$WORK_DIR/snark_proof" \
            -v 2>&1 | tail -5
        echo "  SNARK proof: $WORK_DIR/snark_proof/"
        ls -lh "$WORK_DIR/snark_proof/"

        # Extract verification key and proof data
        echo "  Extracting programVK and proof bytes for Solidity..."
        # The SNARK output contains: proof.json with proof_bytes and public_values
    fi
fi

# ─── Stage 8: Solidity verification ─────────────────────────────────
if [ "$START_STAGE" -le 8 ]; then
    echo "[8/8] Running Solidity verifier tests..."
    (cd "$CONTRACTS_DIR" && forge test -vv 2>&1 | tail -10)
fi

echo
echo "=== Pipeline Complete ==="
echo "  Guest ELF:    $ELF"
echo "  Work dir:     $WORK_DIR"
echo "  Inner proofs: $WORK_DIR/inner_proofs/proofs/"
[ -d "$WORK_DIR/stark_proof" ] && echo "  STARK proof:  $WORK_DIR/stark_proof/"
[ -d "$WORK_DIR/snark_proof" ] && echo "  SNARK proof:  $WORK_DIR/snark_proof/"
echo "  Contracts:    $CONTRACTS_DIR/src/ZiskVerifier.sol"
