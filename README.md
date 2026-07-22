# ZiSK Second Proof System for ZKsync OS

A second proof system for ZKsync OS using ZiSK (RV64IMA zkVM). Runs alongside
the primary airbender (RV32I) proof system, providing independent verification
of state transitions.

> **Start here for the cross-repo picture:** [docs/multiprover.md](docs/multiprover.md)
> covers the full multi-proof lane — proof flow, key pinning, operating
> modes — and maps which repository owns which component.

## Architecture

```
                         ┌─────────────────────────────────┐
                         │     zksync-os-server pipeline    │
                         │                                  │
                         │  BlockExecutor → TreeManager →   │
                         │  ProverInputGenerator → Batcher  │
                         │       │               │          │
                         │  airbender witness  ZiSK input   │
                         │  (Vec<u32>)       (BatchInput)   │
                         └───────┬───────────────┬──────────┘
                                 │               │
                    ┌────────────▼──┐    ┌───────▼────────┐
                    │  Airbender    │    │  ZiSK Prover   │
                    │  RV32I prover │    │  RV64IMA prover│
                    └────────┬──────┘    └───────┬────────┘
                             │                   │
                    ┌────────▼───────────────────▼────────┐
                    │        L1 Smart Contract             │
                    │  Verifies BOTH proofs for each batch │
                    └─────────────────────────────────────┘
```

## Directory Structure

| Directory | What it is |
|-----------|-----------|
| `lib/` | Shared Rust library — REVM executor, merkle proof verification, batch commitment hashing, types. Used by the guest and the server. |
| `guest/` | ZiSK guest binary — compiled to RV64IMA ELF, runs inside the prover. Reads `BatchInput`, executes with proof verification, commits the batch hash. |
| `prover/` | Prover daemon (`zksync-os-zisk-prover-service`) — polls the server's `/ZiSK/*` prover API, drives `cargo-zisk prove --plonk` over the guest ELF, submits proofs. Standalone crate, no Cargo dependency on `lib/`/`guest/`; see its README for fleet deployment. |
Solidity verifiers (`ZiskVerifier.sol`, `ZiskSnarkPlonkVerifier.sol`) live in [era-contracts](https://github.com/antoniolocascio-bot/era-contracts/tree/dev/l1-contracts/contracts/state-transition/verifiers) and are generated via `cargo run -- --variant zisk` in `era-contracts/tools/`.

## What the ZiSK Proof Verifies

Every storage read is verified against a Blake2s merkle proof that recovers
the expected state root. The proof commits a `BatchPublicInput` hash:

- **State before**: Blake2s(tree_root, leaf_count, block_number, block_hashes_blake, timestamp)
- **State after**: Computed from REVM execution + tree update proof
- **Batch hash**: Keccak256(chain_id, timestamps, DA commitment, tx counts, priority ops hash, L2 logs root, ...)
- **Committed output**: Keccak256(state_before || state_after || batch_hash)

Verified inside the proof:
- Storage reads via merkle proofs (every SLOAD)
- Account balances/nonces via preimage hash verification
- L2 transaction signatures via secp256k1 ecrecover
- L1 transaction hash binding (keccak256(encoded_tx) == l1_tx_hash)
- Bytecode integrity (keccak256(code) == code_hash)
- Block header hash from execution results (RLP + keccak256)
- Tree update entries cross-checked against REVM execution diffs

## Server Integration

Enable the second proof system in server config:

```yaml
prover_input_generator:
  second_proof_system: true
```

This generates ZiSK prover input alongside the primary airbender witness
for every block. The ZiSK input includes merkle proofs, account preimages,
and a tree update proof extracted from the server's merkle tree.

## Development

```bash
# Run lib tests (includes the proven-path end-to-end tests)
cd lib && cargo test

# Generate a minimal ZiSK input natively (writes /tmp/proven_input.bin)
cd lib && cargo test export_proven_input_for_emulator
# Print the native reference commitment for those exact bytes
cd lib && cargo test print_input_bin_commitment -- --ignored

# Build guest for ZiSK prover
cargo-zisk build --release   # in guest/

# Run in ZiSK emulator
cargo-zisk execute -e guest/target/riscv64ima-zisk-zkvm-elf/release/zksync-os-zisk-guest -i /tmp/proven_input.bin

# Verify ZiSK constraints (without full proving)
cargo-zisk verify-constraints -e <elf> -i input.bin

# Full proof generation (requires 64GB+ RAM)
./prove_and_verify.sh --input batch.json
```

## Reproducible guest builds

The `programVK` pinned on L1 (and in the server's
`prover_api_config.zisk_program_vk` drift tripwire) is the ROM merkle root
of the guest ELF, so a given source revision must map to exactly one binary.
`docker/guest-builder.Dockerfile` pins everything that influences the build:
the base image, the cargo-zisk release (v0.18.0, which fixes the ZiSK Rust
toolchain it installs), the pinned cargo that orchestrates it, the committed
`guest/Cargo.lock`, and a fixed `/build` source path.

```bash
# Build in the pinned container and verify against the recorded hash
./build-guest.sh

# After an intentional guest change: rebuild, re-record, commit
./build-guest.sh --record   # updates guest/GUEST_ELF_SHA256
```

The ELF lands in `out/zksync-os-zisk-guest`. Derive its `programVK` on a
prover box with `cargo-zisk rom-setup -e out/zksync-os-zisk-guest` and record
it in the server config (`zisk_program_vk`) and, at gating time, the L1
verifier. Determinism is validated: two independent container builds
(toolchain re-downloaded) produce byte-identical ELFs.

## Testing

```bash
# Server integration test (fetches the server-assembled BatchInput from
# /ZiSK/{batch}/peek and re-executes it with this lib's executor; requires
# prover input generation, so run without the no-pig profile)
cd ../zksync-os-server
cargo nextest run -p zksync_os_integration_tests -E 'test(zisk)'
```

## Backend portability

Everything provable lives in the backend-neutral `lib/` (no_std-friendly; the
crypto syscall bindings are behind the ZiSK target). `guest/` is a thin ZiSK
shim: input framing, crypto provider installation, and the 32-byte commit.
Keep new logic in `lib/` so a second zkVM backend stays cheap.

A validated OpenVM (RV32IM) guest for this same lib is preserved on the
`backup/openvm-main` branch (`guest-openvm/`): it reproduced the reference
`BatchPublicInput` end-to-end and proved via app STARK → Halo2/KZG SNARK
(~3.9 KB) in the multi-prover benchmark. To revive it: cherry-pick `guest-openvm/`
from that branch, re-pin its `openvm` crates (v2.0.0-beta.2 at the time), and
re-run the lib's `test_proven` reader against `cargo openvm run` output.
Inputs are passed as type-prefixed hex (`01` + hex via `--input`, JSON file
form for inputs over 128 KB).
