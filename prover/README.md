# ZKsync OS: ZiSK Prover

This crate is the prover service of the ZKsync OS ZiSK (RV64IMA) prover, the second proof system alongside Airbender. [`docs/multiprover.md`](../docs/multiprover.md) covers the lane architecture; this document covers running the daemon.

## Overview

The ZiSK prover generates STARK + SNARK proofs for ZKsync OS batches using the ZiSK zkVM. It runs as an external daemon that polls the sequencer for work, drives proof generation through the ZiSK toolchain, and submits the results back for multi-proof composition with Airbender.

The daemon has two proving backends:

- **Per-proof process** (default, ZiSK v0.18.0). Each proof runs one `cargo-zisk prove` process, which loads the proving keys and initializes the GPU on every invocation.
- **Resident prover service** (`--coordinator-url`). The daemon shells `zisk-prove-client` calls against a long-lived `zisk-coordinator`; its `zisk-worker` holds the proving keys and the GPU, so they load once for the service lifetime. All three binaries belong to ZiSK v0.18.0: `ziskup` installs the coordinator and the worker, and `zisk-prove-client` builds from the ZiSK source tree (`cargo build --release -p zisk-prove-client`).

### Architecture

```
Sequencer (zksync-os-server)
    │
    ├── /ZiSK/pick      → ZiSK batch data (BatchInput, bincode)
    ├── /ZiSK/submit    ← per-batch vadcop_final stream (336168 bytes)
    │
    ├── /ZiSK-AGG/pick  → one batch range's buffered streams
    └── /ZiSK-AGG/submit ← range SNARK (768 bytes) + public values (320 bytes)
                         │
                         ▼
              MultiProofSnarkProof (Airbender + ZiSK combined)
                         │
                         ▼
                    L1 verification
```

Every route sits under `/prover-jobs/v1/`.

### Proof Pipeline

At startup the daemon runs a one-time setup per guest ELF: `cargo-zisk program-setup` in the default backend, `zisk-prove-client setup` against the coordinator otherwise (the coordinator content-addresses the ELF by its blake3 hash and reuses an existing setup).

The server always aggregates, so run the daemon with `--aggregation` and `--aggregator-elf`. The daemon then drives two proving flows:

1. **Per batch.** One `cargo-zisk prove` invocation executes the ZiSK guest ELF and aggregates the per-AIR proofs into a verified `vadcop_final` proof. The daemon extracts the 336168-byte proof stream and submits it with empty public values; the stream carries its own publics.
2. **Per batch range.** One `cargo-zisk prove --plonk` invocation runs the aggregator guest over the range's streams, verifies each inner proof inside the zkVM, and wraps the result in a BN254 Plonk SNARK for on-chain verification. The daemon parses that output into the 768-byte SNARK proof and the 320-byte public values (`program VK ‖ publics ‖ vadcop-final VK`).

Without `--aggregation` the daemon proves each batch with the PLONK wrap directly. That mode drives the toolchain standalone; the sequencer's `/ZiSK/submit` route accepts the stream shape only.

On an RTX 5090, per-batch proving runs from ~12 s (small batch) to ~80 s (1000-transfer batch), dominated by the STARK phase; the Plonk wrap is ~5–7 s and batch-size independent. In the default backend each proof also pays the proving-key load and the GPU initialization, which take about 4.5 minutes; the resident-service backend pays them once and then proves in 19–21 s.

## Prerequisites

- **ZiSK toolchain v0.18.0** (`ziskup -v 0.18.0`): `cargo-zisk` for the default backend, `zisk-prove-client` (built from the ZiSK source tree) for the coordinator backend; the selected binary's path is passed as `--zisk-binary`.
- **ZiSK guest ELFs**: built from `zksync-os-zisk/guest/` and `zksync-os-zisk/guest-aggregator/` via the reproducible builds (`./build-guest.sh`, `./build-aggregator.sh`); their paths are passed as `--elf-path` and `--aggregator-elf`.
- **STARK proving key**: `~/.zisk/provingKey/` (via `ziskup`), passed as `--proving-key`.
- **PLONK proving key**: `~/.zisk/provingKeySnark/` (via `ziskup setup_snark`), passed as `--proving-key-plonk`.
- **libgmp-dev**: required by the assembly generation in `program-setup` (`-lgmp`/`-lgmpxx`)
- **GPU**: NVIDIA with 16 GB or more of VRAM (CUDA)

With `--coordinator-url`, the proving keys and the GPU move to the `zisk-worker` behind the coordinator, and the daemon needs only the toolchain and the guest ELFs.

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
  --aggregation --aggregator-elf /path/to/zksync-os-zisk-guest-aggregator \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark
```

### With authentication

```bash
cargo run --release -- \
  --sequencer-url http://user:password@sequencer.example.com:3124 \
  ...
```

### With VK hash filtering

Only prove batches matching specific verification key hashes:

```bash
cargo run --release -- \
  ... \
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
| `--zisk-binary` | required | Toolchain binary the daemon shells: `cargo-zisk` in the default backend, `zisk-prove-client` under `--coordinator-url`. |
| `--elf-path` | required | Path to the ZiSK state-transition guest ELF. |
| `--proving-key` | required | ZiSK STARK proving key directory. Omit it under `--coordinator-url`; the worker supplies it. |
| `--proving-key-plonk` | required | ZiSK PLONK proving key directory. Omit it under `--coordinator-url`; the worker supplies it. |
| `--aggregation` | off | Aggregated mode, which the server requires. Submits per-batch `vadcop_final` streams and proves `/ZiSK-AGG` range jobs. Requires `--aggregator-elf`. |
| `--aggregator-elf` | (none) | Path to the ZiSK aggregator guest ELF. Requires `--aggregation`. |
| `--no-gpu` | off | Prove CPU-only. Conflicts with `--coordinator-url`. |
| `--asm-emulator` | off | Use the ASM emulator for witness generation. It is faster, and it needs a high memlock ulimit; the default standard emulator (`--emulator`) runs anywhere. Conflicts with `--coordinator-url`. |
| `--coordinator-url` | (none) | ZiSK coordinator gRPC URL (env `ZISK_COORDINATOR_URL`), typically `http://localhost:7000`. Selects the resident-service backend, whose worker holds the proving keys and GPU; `--zisk-binary` must then point at `zisk-prove-client`. |
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
| `zisk_prover_http_latency` | Histogram | HTTP latency, labelled by method (`pick`, `submit`, `pick_aggregation`, `submit_aggregation`) |
| `zisk_prover_proof_generation_time` | Histogram | Total proof time per batch or range |
| `zisk_prover_prove_time` | Histogram | Toolchain prove time (STARK, plus the PLONK wrap where the flow uses it) |
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
  --aggregation --aggregator-elf /path/to/zksync-os-zisk-guest-aggregator \
  --proving-key ~/.zisk/provingKey \
  --proving-key-plonk ~/.zisk/provingKeySnark
```

The sequencer's ZiSK job API is a job market, so several daemons can share it:
each independently picks a batch, proves it, and submits. Give each daemon a
distinct `--work-dir`, a distinct `--metrics-address` port, and an explicit
`--prover-id` (it defaults to the hostname) so concurrent daemons are
distinguishable in server logs.

### Resident prover service

A coordinator and its workers keep the proving keys and the GPU loaded
across proofs. Start the coordinator first; it serves clients on port 7000
and workers on the internal cluster port 50051:

```bash
# 1. Coordinator: client API on 7000, worker cluster port on 50051.
zisk-coordinator

# 2. Worker: proving keys + GPU, joined to the coordinator's CLUSTER port
#    through its TOML config ([coordinator] url = "http://127.0.0.1:50051").
#    --plonk wires the PLONK key (without it the wrap jobs fail);
#    --emulator selects the standard emulator (the ASM path needs a high
#    memlock ulimit); --gpu proves on the GPU. The worker registers only
#    after the full key load (several minutes) — jobs submitted before the
#    coordinator logs "Registered worker:" fail with "no workers connected".
CUDA_VISIBLE_DEVICES=0 zisk-worker \
  --config worker.toml \
  --proving-key ~/.zisk/provingKey \
  --proving-key-snark ~/.zisk/provingKeySnark \
  --emulator --gpu --plonk

# 3. Daemon: shells zisk-prove-client against the coordinator's API port.
zksync-os-zisk-prover-service \
  --sequencer-url http://sequencer:3124 \
  --coordinator-url http://localhost:7000 \
  --zisk-binary /path/to/zisk-prove-client \
  --elf-path /path/to/zksync-os-zisk-guest \
  --aggregation --aggregator-elf /path/to/zksync-os-zisk-guest-aggregator
```

`ziskup` installs the coordinator and the worker. Build `zisk-prove-client`
from the ZiSK v0.18.0 source tree with
`cargo build --release -p zisk-prove-client`.

Proving throughput then scales on the worker side: join more workers to the
same coordinator (each with its own TOML config at the cluster port and its
own `CUDA_VISIBLE_DEVICES` GPU pin). The coordinator distributes proving work
across its worker pool while the daemon stays a single thin client.

Server side: set the sequencer's ZiSK assignment timeout comfortably above the
worst-case proving time for your batch sizes, or jobs are reassigned mid-proof
and the late submission is rejected as `UnknownJob` (harmless, but wasted
work). A daemon running a stale guest build is caught by the server's VK drift
tripwires (`zisk_lane_vk_drift`, `zisk_lane_aggregated_vk_drift`) when
`prover_api.zisk_vks` and `prover_api.zisk_aggregation.program_vk` are
configured.

## License

ZKsync OS repositories are distributed under the terms of either

- Apache License, Version 2.0, <http://www.apache.org/licenses/LICENSE-2.0>
- MIT license, <https://opensource.org/blog/license/mit/>

at your option.
