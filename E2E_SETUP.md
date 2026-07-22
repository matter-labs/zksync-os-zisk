You are setting up and running the ZiSK second proof system for ZKsync OS end-to-end, including STARK proof generation, SNARK wrapping, and Solidity verification.

## Machine requirements

- NVIDIA GPU with 16GB+ VRAM (CUDA required)
- 64GB+ system RAM
- 50GB+ free disk
- Ubuntu 22.04 or 24.04

## Step 1: Install toolchains

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup install nightly-2026-02-10

# ZiSK toolchain
curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
source ~/.bashrc

```

## Step 2: Clone repositories

```bash
mkdir ~/zksync-os-second-proof-system && cd ~/zksync-os-second-proof-system

# Main ZiSK proof system
git clone -b dev https://github.com/antoniolocascio-bot/zksync-os-zisk

# Server (for integration tests, optional on this machine)
git clone -b dev https://github.com/antoniolocascio-bot/zksync-os-server
```

## Step 3: Run the full proof pipeline

```bash
cd ~/zksync-os-second-proof-system/zksync-os-zisk

# Run stages 1-5 first (build, prepare input, emulate, inner STARK proofs)
ZISK_WORK_DIR=/tmp/zisk_e2e ./prove_and_verify.sh
```

This runs 8 stages:
1. Build guest ELF (RV64IMA binary)
2. Prepare sample batch input
3. ROM setup (per-ELF proving key)
4. Emulate + verify constraints
5. STARK inner proofs (19 per-AIR FRI proofs)
6. STARK aggregation + compression (vadcop_final) — **needs 64GB RAM + GPU**
7. SNARK wrapping (Plonk proof) — **needs SNARK proving key**
8. Solidity verification

## Step 4: If stage 6 skips (SNARK proving key missing)

The SNARK proving key is a separate ~5GB download. Check ZiSK releases:
```bash
# Check if ziskup already downloaded it
ls ~/.zisk/provingKeySnark 2>/dev/null || echo "Need to download SNARK key"

# If missing, download from ZiSK releases (check https://github.com/0xPolygonHermez/zisk/releases)
# Place at ~/.zisk/provingKeySnark/
```

Then rerun stage 7:
```bash
ZISK_WORK_DIR=/tmp/zisk_e2e ./prove_and_verify.sh --stage 7
```

## Step 5: Extract verification artifacts

After the full pipeline completes, collect these artifacts:

```bash
# 1. programVK — the ELF-specific verification key (4 uint64s)
#    Printed during rom-setup: "Root hash: [a, b, c, d]"
#    This is what identifies this specific ZiSK guest binary

# 2. rootCVadcopFinal — from SNARK setup
#    Stored in ~/.zisk/provingKeySnark/vadcop_final.verkey.json

# 3. SNARK proof bytes — from the stage 7 output
ls /tmp/zisk_e2e/snark_proof/

# 4. Public values — the 32-byte BatchPublicInput hash
#    Committed by the guest via ziskos::io::commit()
```

## Step 6: Update and verify on-chain verifier

Once you have the SNARK proof from stage 7, update the ZiSK verifier in era-contracts:

```bash
cd ~/zksync-os-second-proof-system/era-contracts/tools

# Update ZiSK_vk.json with new programVK (from rom-setup output)
# Then regenerate:
cargo run --release -- --variant zisk

# Copy to contracts dir:
cp data/ZiskVerifier.sol ../../l1-contracts/contracts/state-transition/verifiers/

# Run verifier tests:
cd ../../l1-contracts && forge test --match-contract MultiProofVerifier
```

## What to verify at each stage

- **Stage 4**: "Emulation passed" + "All global constraints verified"
- **Stage 5**: "19 AIR proofs saved" + "GENERATING_INNER_PROOFS" completes
- **Stage 6**: "GENERATING_INNER_PROOFS" + aggregation + compression completes without OOM
- **Stage 7**: SNARK proof file generated
- **Stage 8**: era-contracts `forge test --match-contract MultiProofVerifier` passes

## Troubleshooting

- If stage 6 OOMs: check `free -h` during proving, need 64GB+ RAM
- If CUDA errors: verify `nvidia-smi` works and CUDA toolkit is installed
- If stage 4 emulation panics about "missing signed_tx_bytes": use the proven input from the test (Step 3 above)
- The `--emulator` flag in `prove_and_verify.sh` uses the Rust emulator instead of ASM microservices — needed if the ASM process hangs
