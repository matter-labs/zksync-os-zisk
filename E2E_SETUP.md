# End-to-end setup

This guide brings up the ZiSK second proof system for ZKsync OS on one
machine: the reproducible guest builds, the per-ELF program setup, real
proof generation on a GPU, and the on-chain verification in era-contracts.

## Machine requirements

- NVIDIA GPU with 16 GB or more of VRAM (CUDA)
- 64 GB or more of system RAM
- 100 GB or more of free disk (the ZiSK proving keys are large)
- Ubuntu 22.04 or 24.04
- Docker, for the reproducible guest builds

## Step 1: Install the toolchains

```bash
# Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# ZiSK toolchain, pinned at v1.2.0-alpha
curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash
source ~/.bashrc
ziskup -v 1.2.0-alpha

# PLONK proving key (a separate, multi-gigabyte download)
ziskup setup_snark
```

`ziskup` installs `cargo-zisk`, `ziskemu`, `zisk-coordinator` and
`zisk-worker` into `~/.zisk/bin`, the STARK proving key into
`~/.zisk/provingKey`, and the PLONK proving key into
`~/.zisk/provingKeySnark`.

The resident-prover backend also needs `zisk-prove-client`. Build it from
the ZiSK source tree at the pinned release:

```bash
git clone --branch v1.2.0-alpha https://github.com/0xPolygonHermez/zisk zisk-src
cd zisk-src && cargo build --release -p zisk-prove-client
```

## Step 2: Clone the repositories

```bash
mkdir ~/zksync-os-second-proof-system && cd ~/zksync-os-second-proof-system

git clone -b dev https://github.com/antoniolocascio-bot/zksync-os-zisk
git clone -b dev https://github.com/antoniolocascio-bot/zksync-os-server
git clone -b dev https://github.com/antoniolocascio-bot/era-contracts
```

## Step 3: Build the guest ELFs reproducibly

```bash
cd ~/zksync-os-second-proof-system/zksync-os-zisk
./build-guest.sh
./build-aggregator.sh
```

Each script builds inside its pinned container and compares the fresh
sha256 against the recorded hash in `guest/GUEST_ELF_SHA256` and
`guest-aggregator/GUEST_ELF_SHA256`. The ELFs land in `out/`. A hash
mismatch means the source and the recorded pin disagree; resolve that
before you prove anything.

## Step 4: Run the per-ELF program setup

The `programVK` is the ROM merkle root of an ELF. Derive it once per ELF:

```bash
cargo-zisk setup -e out/zksync-os-zisk-guest -k ~/.zisk/provingKey
cargo-zisk setup -e out/zksync-os-zisk-guest-aggregator \
    -k ~/.zisk/provingKey
```

The setup runs on the CPU and writes the verkey into `~/.zisk/cache`; set
`ZISK_CACHE_DIR` to collect it elsewhere. The command prints the four ROM
root-hash u64 limbs. Compare them against
`guest/GUEST_PROGRAM_VK` and `guest-aggregator/GUEST_PROGRAM_VK`, which hold
both the limbs and the 32-byte big-endian value the wire format uses.

## Step 5: Prove one batch

Export a sample input and prove it with the PLONK wrap:

```bash
cd lib && cargo test export_proven_input_for_emulator && cd ..

cargo-zisk prove \
    -e out/zksync-os-zisk-guest \
    -i /tmp/proven_input.bin \
    -k ~/.zisk/provingKey \
    -w ~/.zisk/provingKeySnark --plonk \
    -y -o /tmp/proof.bin -g
```

The standard emulator runs anywhere and is the default. `-a` selects the ASM
emulator, which is faster and needs a high memlock ulimit, so containers with
an 8 MB memlock limit leave it off.

The output file is bincode of ZiSK's `Proof` struct. It carries the
768-byte BN254 PLONK proof, the 256-byte publics region, the program VK and
the vadcop-final VK. Decode it with the daemon's inspector:

```bash
cd prover && cargo run --bin inspect_proof -- /tmp/proof.bin
```

It prints the 576-byte wire public values
`programVK (32) ‖ publics (512) ‖ vadcopVK (32)`, with the batch commitment
at bytes `[32..96]`.

To keep the intermediate `vadcop_final` STARK stream instead — the artifact
the aggregator guest verifies, and the artifact the server accepts per
batch — run the same command without `-w` and `--plonk`. The stream is
336168 bytes.

## Step 6: Run the prover daemon against a sequencer

Enable the second proof system in the sequencer config:

```yaml
prover_input_generator:
  second_proof_system: true
```

Then start the daemon in aggregated mode, which is the mode the server
accepts:

```bash
cd prover
cargo run --release -- \
  --sequencer-url http://localhost:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path ../out/zksync-os-zisk-guest \
  --aggregation --aggregator-elf ../out/zksync-os-zisk-guest-aggregator \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark
```

`prover/README.md` covers the two proving backends, every CLI flag, the
metrics, and the resident coordinator deployment that keeps the proving
keys and the GPU loaded across proofs.

## Step 7: Verify on-chain

Update the ZiSK verifier in era-contracts with the pins from Step 4, then
regenerate and test it:

```bash
cd ~/zksync-os-second-proof-system/era-contracts/tools

# Put the ROM root limbs of both guests, and rootCVadcopFinal, into
# data/ZiSK_vk.json, then regenerate the verifier.
npm ci
node render_plonk_verifier.js data/ZiSK_plonk_verification_key.json \
    data/PlonkVerifier.sol
cargo run -- --variant zisk

cd ../l1-contracts && forge test --match-contract ZiskVerifier
```

`era-contracts/l1-contracts/contracts/state-transition/verifiers/README.md`
holds the full generation and deployment procedure, including the exact
paths of the generated contracts.

## What to check at each step

- **Step 3**: both scripts print `OK: matches recorded hash.`
- **Step 4**: the printed root-hash limbs match the committed
  `GUEST_PROGRAM_VK` files.
- **Step 5**: `/tmp/proof.bin` exists, and `inspect_proof` reports a
  768-byte proof with 320 bytes of public values.
- **Step 6**: the daemon logs `proof submitted`, and the server accepts the
  submission without a VK-drift error.
- **Step 7**: the era-contracts foundry suite passes.

## Troubleshooting

- Aggregation runs out of memory: check `free -h` during proving. The
  aggregation stage needs 64 GB or more of RAM.
- CUDA errors: check that `nvidia-smi` works and that the CUDA toolkit is
  installed.
- The ASM emulator hangs or fails to lock memory: drop `-a` to use the
  standard emulator.
- `cargo-zisk` fails to start with `libmpi.so.40: cannot open shared object
  file`: install `openmpi-bin`, or extract the runtime libraries into a user
  directory and export `LD_LIBRARY_PATH`.
- Step 5 panics about a missing field in the input: export the sample input
  again with the `lib` test in Step 5, so the wire version matches the guest.
