# ZiSK Second Proof System for ZKsync OS

A second proof system for ZKsync OS that uses ZiSK, an RV64IMA zkVM. It runs
alongside the primary Airbender (RV32I) proof system and verifies each state
transition independently. L1 verification requires both proofs.

This repository holds an independent re-implementation of the ZKsync OS
state transition on REVM, the zkVM guests that prove it, the proving daemon,
and the off-chain verification helpers the server calls.

| Read this | For |
|---|---|
| [docs/multiprover.md](docs/multiprover.md) | The architecture: system flow, the independence invariant, wire formats, key pinning, and the rollout ladder. |
| [prover/README.md](prover/README.md) | Operations: the daemon, its two proving backends, every flag, the metrics, and fleet deployment. |
| [E2E_SETUP.md](E2E_SETUP.md) | Bring-up on one machine, from toolchain install to on-chain verification. |
| [guest-aggregator/BINDING_VECTOR.md](guest-aggregator/BINDING_VECTOR.md) | The cross-stack test vector for the aggregated-range binding digest. |
| [tools/CORPUS.md](tools/CORPUS.md) | The EEST conformance lane. |

## Repository layout

| Directory | What it is |
|-----------|-----------|
| `lib/` | The independent state-transition re-implementation on REVM — executor, merkle proof verification, batch commitment hashing, types. The guest and the server both use it. |
| `guest/` | The ZiSK state-transition guest — the RV64IMA ELF entry point around `lib/`. `GUEST_ELF_SHA256` and `GUEST_PROGRAM_VK` record its pinned identity. |
| `guest-aggregator/` | The ZiSK range-aggregator guest — verifies one per-batch proof per batch inside the zkVM and commits the range binding digest. |
| `prover/` | The proving daemon (`zksync-os-zisk-prover-service`) — polls the server's `/ZiSK/*` and `/ZiSK-AGG/*` job API, drives the ZiSK toolchain over both ELFs, and submits the results. |
| `zisk-verifier/` | Off-chain verification helpers. The server calls them to check a submitted proof before it composes the L1 payload. |
| `tools/` | The committed EEST native-reference corpus and target-emulation lane, the guest-memory benchmark, and host-side input assemblers. |
| `docker/` | The pinned containers of the reproducible guest builds. |

The Solidity verifiers live in
[era-contracts](https://github.com/antoniolocascio-bot/era-contracts):
`ZiskVerifier.sol` in
`l1-contracts/contracts/state-transition/verifiers/` and the generated
`ZiskSnarkPlonkVerifier.sol` in
`l1-contracts/contracts/dev-contracts/generated/`. Regenerate both from
`era-contracts/tools/` with `cargo run -- --variant zisk`; that repository's
`l1-contracts/contracts/state-transition/verifiers/README.md` holds the full
procedure.

## Reproducible guest builds

Each `programVK` pinned on L1 and in the server's drift tripwires is the ROM
merkle root of a guest ELF, so a given source revision must map to exactly
one binary. `docker/guest-builder.Dockerfile` and
`docker/aggregator-builder.Dockerfile` pin everything that influences the
build: the base image, the cargo-zisk release (v0.18.0, which fixes the ZiSK
Rust toolchain it installs), the pinned cargo that orchestrates it, the
committed `Cargo.lock`, and a fixed `/build` source path.

```bash
# Build in the pinned containers and verify against the recorded hashes
./build-guest.sh
./build-aggregator.sh

# After an intentional guest change: rebuild, re-record, commit
./build-guest.sh --record        # updates guest/GUEST_ELF_SHA256
./build-aggregator.sh --record   # updates guest-aggregator/GUEST_ELF_SHA256
```

The ELFs land in `out/zksync-os-zisk-guest` and
`out/zksync-os-zisk-guest-aggregator`. CI runs both scripts on every push,
so a source change in `lib/`, `guest/` or `guest-aggregator/` turns the
build red until the recorded hash follows it. Determinism is validated: two
independent container builds, with the toolchain downloaded again, produce
byte-identical ELFs.

Derive a `programVK` on a prover box, which holds the proving keys, and
record it in `guest/GUEST_PROGRAM_VK` or
`guest-aggregator/GUEST_PROGRAM_VK`:

```bash
cargo-zisk program-setup -e out/zksync-os-zisk-guest -k ~/.zisk/provingKey
```

The manually dispatched `Rotate program VK pins` workflow performs that
derivation for both reproducible ELFs on the high-performance runner. Its
`base_ref` must contain the reviewed `GUEST_ELF_SHA256` pins. When either
program VK differs within the selected `rotation_scope`, the workflow opens a
draft PR containing the pin changes, derivation provenance, ELF digests,
canonical VKs, and root limbs. A difference outside that explicit scope fails
the run. A run with current pins records the same identities in its job summary
without creating a PR.

## Release assets

A published GitHub release starts the release-assets workflow. Alongside the
guest-ELF and host-tool tarballs, a high-performance runner rebuilds both ELFs,
checks their committed SHA-256 pins, and derives both program VKs with the CPU
ZiSK package and the STARK proving key. It also reads the vadcop-final VK from
that proving key and computes the ZiSK VK hash:

```text
keccak256(innerProgramVK || aggregatorProgramVK || rootCVadcopFinal)
```

The release carries the guest-ELF and host-tool tarballs plus a verification-
key tarball with these files:

| File in `zksync-os-zisk-verification-keys-<tag>.tar.gz` | Contents |
|---|---|
| `*.verkey.bin` | Raw ZiSK VK files with four little-endian u64 limbs. |
| `zisk-release.json` | Schema-v1 identity: release and toolchain, both ELFs and VKs, vadcop root, guest/host archives, prover-service digest, and the combined ZiSK VK hash. |

Consumers pin a release tag, extract the verification-key tarball, and read
the canonical keys and artifact digests from `zisk-release.json`. The manifest
associates each full ELF hash with the program VK derived from that ELF and
also pins the two release archives and the host prover binary. The release job
checks the derived program VKs against the two committed `GUEST_PROGRAM_VK`
pins before it uploads any asset. Its job summary presents the ELF digests,
canonical VKs, root limbs, toolchain version, and ZiSK VK hash before upload.

[docs/multiprover.md](docs/multiprover.md) covers where each pin then lands
in the server's compiled release registry and in the L1 verifier.

## Development

The ZiSK toolchain is pinned at v0.18.0. Install it with
`ziskup -v 0.18.0`.

```bash
# Run lib tests (includes the proven-path end-to-end tests)
cd lib && cargo test

# Generate a minimal ZiSK input natively (writes /tmp/proven_input.bin)
cd lib && cargo test export_proven_input_for_emulator
# Print the native reference commitment for those exact bytes
cd lib && cargo test print_input_bin_commitment -- --ignored

# Run the guest ELF in the ZiSK emulator over that input
ziskemu -e out/zksync-os-zisk-guest -i /tmp/proven_input.bin

# Execute it through the full proving pipeline, without a proof
cargo-zisk execute -e out/zksync-os-zisk-guest -i /tmp/proven_input.bin \
    --emulator -k ~/.zisk/provingKey

# Replay the committed EEST native-reference corpus (the pull-request gate)
cargo build --release --manifest-path tools/test-utils/Cargo.toml \
    --bin dump_to_batchinput
tools/run-eest-native.py \
    --reader tools/test-utils/target/release/dump_to_batchinput \
    --output /tmp/zisk-eest-native

# Prove one batch end to end (needs a GPU and both proving keys)
cargo-zisk program-setup -e out/zksync-os-zisk-guest -k ~/.zisk/provingKey -g
cargo-zisk prove -e out/zksync-os-zisk-guest -i /tmp/proven_input.bin \
    -k ~/.zisk/provingKey -w ~/.zisk/provingKeySnark --plonk \
    -y -o /tmp/proof.bin -g --emulator
```

The ASM emulator is faster and needs a high memlock ulimit. Pass
`--emulator` to select the standard emulator, which runs anywhere.

Server integration test (it fetches the server-assembled `BatchInput` from
`/ZiSK/{batch}/peek` and re-executes it with this lib's executor, so it
needs prover input generation — run it outside the `no-pig` profile):

```bash
cd ../zksync-os-server
cargo nextest run -p zksync_os_integration_tests -E 'test(zisk)'
```

## Backend portability

Everything provable lives in the backend-neutral `lib/` (`no_std`-friendly;
the crypto syscall bindings sit behind the ZiSK target). `guest/` is a thin
ZiSK shim: input framing, crypto provider installation, and the 32-byte
commit. Keep new logic in `lib/` so a second zkVM backend stays cheap.

A validated OpenVM (RV32IM) guest for this same lib is preserved on the
`backup/openvm-main` branch (`guest-openvm/`): it reproduced the reference
`BatchPublicInput` end to end and proved via app STARK → Halo2/KZG SNARK
(~3.9 KB) in the multi-prover benchmark. To revive it: cherry-pick
`guest-openvm/` from that branch, re-pin its `openvm` crates (v2.0.0-beta.2
at the time), and re-run the lib's `test_proven` reader against
`cargo openvm run` output. Inputs are passed as type-prefixed hex (`01` plus
hex via `--input`, JSON file form for inputs over 128 KB).
