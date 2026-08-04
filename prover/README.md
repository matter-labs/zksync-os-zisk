# ZKsync OS: ZiSK Prover

This repo contains the Prover Service implementation for ZKsync OS ZiSK (RV64IMA) prover, the second proof system alongside Airbender.

## Overview

The ZiSK prover generates STARK + SNARK proofs for ZKsync OS batches using the ZiSK zkVM. It runs as an external daemon that polls the sequencer for work, drives proof generation through `cargo-zisk`, and submits the results back for multi-proof composition with Airbender.

The daemon has two proving backends:

- **Per-proof process** (default, ZiSK v0.18.0). Each proof runs one `cargo-zisk prove` process, which loads the proving keys and initializes the GPU on every invocation.
- **Resident prover service** (`--coordinator-url`). The daemon becomes a thin `cargo-zisk remote` client of a long-lived `zisk-coordinator`; its `zisk-worker` holds the proving keys and the GPU, so they load once for the service lifetime. The `remote` subcommand starts at ZiSK v1.0.0-alpha.

### Architecture

```
Sequencer (zksync-os-server)
    │
    ├── /ZiSK/pick  → ZiSK batch data (BatchInput, bincode)
    │
    └── /ZiSK/submit ← ZiSK SNARK proof (768 bytes) + public values (320 bytes)
                         │
                         ▼
              MultiProofSnarkProof (Airbender + ZiSK combined)
                         │
                         ▼
                    L1 verification
```

### Proof Pipeline

At startup the daemon runs a one-time setup for the guest ELF: `cargo-zisk program-setup` in the default backend, `cargo-zisk remote setup` against the coordinator otherwise. For each batch it then runs a single `cargo-zisk prove --plonk` invocation (ZiSK v0.18.0) that:

1. Executes the ZiSK guest ELF and generates + aggregates per-AIR proofs into a verified vadcop final proof.
2. Wraps it into a BN254 Plonk SNARK suitable for on-chain verification.

The output file is parsed into the 768-byte SNARK proof and the 320-byte public values (`program VK ‖ publics ‖ vadcop-final VK`) the sequencer expects. On an RTX 5090, proving runs from ~12 s (small batch) to ~80 s (1000-transfer batch), dominated by the STARK phase; the Plonk wrap is ~5–7 s and batch-size independent. In the default backend each proof also pays the proving-key load and the GPU initialization, which take several minutes; the resident-service backend pays them once.

## Prerequisites

- **ZiSK toolchain v0.18.0**: `cargo-zisk` in PATH ([install](https://github.com/0xPolygonHermez/zisk)); its path is passed as `--zisk-binary`.
- **ZiSK guest ELF**: built from `zksync-os-zisk/guest/` via the reproducible build (`./build-guest.sh`); its path is passed as `--elf-path`.
- **STARK proving key**: `~/.zisk/provingKey/` (via `ziskup`), passed as `--proving-key`.
- **PLONK proving key**: `~/.zisk/provingKeySnark/` (via `ziskup setup_snark`), passed as `--proving-key-plonk`.
- **libgmp-dev**: required by the assembly RomSetup (`-lgmp`/`-lgmpxx`)
- **GPU**: NVIDIA with 16GB+ VRAM (CUDA)

With `--coordinator-url`, the proving keys and the GPU move to the `zisk-worker` behind the coordinator, and the daemon needs only the toolchain and the guest ELF.

## Usage

Before starting, make sure your **sequencer** has ZiSK proving enabled:

```yaml
prover_input_generator:
  second_proof_system: true
```

### Start the daemon

```bash
cargo run --release -- \
  --sequencer-url http://localhost:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark
```

### With authentication

```bash
cargo run --release -- \
  --sequencer-url http://user:password@sequencer.example.com:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark
```

### With VK hash filtering

Only prove batches matching specific verification key hashes:

```bash
cargo run --release -- \
  --sequencer-url http://localhost:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark \
  --supported-vk 0x21a582e2fb44e0732b565ffe36331ffb77a315870076b1dc1556579bbc4a67b2
```

Or load from a file:

```bash
cargo run --release -- \
  ... \
  --vk-hashes-file supported_vk_hashes.txt
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--sequencer-url` | required | Sequencer URL. Supports `http://user:pass@host:port`. |
| `--zisk-binary` | required | Path to `cargo-zisk` binary. |
| `--elf-path` | required | Path to ZiSK guest ELF. |
| `--proving-key` | required | ZiSK STARK proving key directory. Supplied by the worker under `--coordinator-url`. |
| `--proving-key-plonk` | required | ZiSK PLONK proving key directory. Supplied by the worker under `--coordinator-url`. |
| `--no-gpu` | off | Prove CPU-only. |
| `--asm-emulator` | off | Use the ASM emulator for witness generation. It is faster, and it needs a high memlock ulimit; the default standard emulator (`--emulator`) runs anywhere. |
| `--coordinator-url` | (none) | ZiSK coordinator gRPC URL (env `ZISK_COORDINATOR_URL`), typically `http://localhost:7000`. Selects the resident-service backend, whose worker holds the proving keys and GPU. Needs a `cargo-zisk` with the `remote` subcommand (ZiSK v1.0.0-alpha and later). |
| `--work-dir` | `/tmp/zisk_proofs` | Intermediate proof files (cleaned after each proof). |
| `--poll-interval-secs` | `5` | Seconds between polls when no work available. |
| `--iterations` | `0` | Exit after N proofs (0 = unlimited). |
| `--supported-vk` | (none) | Accepted VK hashes. Repeatable. Empty = accept all. |
| `--vk-hashes-file` | (none) | File with VK hashes (one per line, # comments). |
| `--metrics-address` | `0.0.0.0:3313` | Prometheus metrics endpoint. |
| `--prover-id` | hostname | Identity reported to the sequencer's job API; shows up in server-side assignment/reassignment logs. |

### Metrics

Prometheus metrics are served at `--metrics-address` (default `:3313`):

| Metric | Type | Description |
|--------|------|-------------|
| `zisk_prover_http_latency` | Histogram | HTTP pick/submit latency |
| `zisk_prover_proof_generation_time` | Histogram | Total proof time per batch |
| `zisk_prover_prove_time` | Histogram | `cargo-zisk` prove time (STARK + PLONK wrap) |
| `zisk_prover_program_setup_time` | Histogram | One-time per-ELF program setup |
| `zisk_prover_proofs` | Counter | Proof attempts by outcome (success/failure/cancelled) |

## Deployment

The single-machine Prividium layout runs the daemon on the box that holds the
proving keys and the GPU:

```bash
zksync-os-zisk-prover-service \
  --sequencer-url http://sequencer:3124 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark
```

The sequencer's ZiSK job API is a job market, so several daemons can share it:
each independently picks a batch, proves it, and submits. Give each daemon a
distinct `--work-dir`, a distinct `--metrics-address` port, and an explicit
`--prover-id` (it defaults to the hostname) so concurrent daemons are
distinguishable in server logs.

### Resident prover service

On a toolchain with `cargo-zisk remote` (ZiSK v1.0.0-alpha and later), a
coordinator and its workers keep the proving keys and the GPU loaded across
proofs. Start the coordinator first; it exposes a client-facing API port and a
worker-facing cluster port:

```bash
# 1. Coordinator: client-facing API on 7000, worker-facing cluster on 7001.
zisk-coordinator --api-port 7000 --cluster-port 7001

# 2. Worker: proving keys + GPU, joined to the coordinator's cluster port.
#    --preload-plonk loads the PLONK key up front so the wrap runs without a
#    per-proof reload.
CUDA_VISIBLE_DEVICES=0 zisk-worker \
  --coordinator-url http://localhost:7001 \
  --proving-key ~/.zisk/provingKey \
  --proving-key-snark ~/.zisk/provingKeySnark \
  --preload-plonk

# 3. Daemon: thin client pointed at the coordinator's API port.
zksync-os-zisk-prover-service \
  --sequencer-url http://sequencer:3124 \
  --coordinator-url http://localhost:7000 \
  --zisk-binary ~/.zisk/bin/cargo-zisk \
  --elf-path /path/to/zksync-os-zisk-guest
```

Proving throughput then scales on the worker side: join more workers to the
same coordinator (each with `--coordinator-url` at the cluster port and its own
`CUDA_VISIBLE_DEVICES` GPU pin). The coordinator distributes proving work
across its worker pool while the daemon stays a single thin client.

Server side: set the sequencer's ZiSK assignment timeout comfortably above the
worst-case proving time for your batch sizes, or jobs are reassigned mid-proof
and the late submission is rejected as `UnknownJob` (harmless, but wasted
work). A daemon running a stale guest build is caught by the server's VK drift
tripwire (`zisk_lane_vk_drift`) when `zisk_program_vk` is configured.

## License

ZKsync OS repositories are distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/blog/license/mit/>)

at your option.
