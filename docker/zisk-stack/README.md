# ZiSK proving stack image

One image, `zksync-os-zisk-prover`, runs the ZiSK second proof system on a
GPU machine in coordinator mode: the proving keys and the GPU load once into
a resident worker, and every proof after that reuses them. The image holds
all four programs; the container command picks one.

| Command | Role | Needs |
|---|---|---|
| `zisk-coordinator --config /etc/zisk/coordinator.toml` | Job queue and client API | CPU only |
| `zisk-worker --config /etc/zisk/worker.toml ...` | Proves. Holds the STARK and PLONK proving keys resident | an NVIDIA GPU, the key volume |
| `zksync-os-zisk-prover-service ...` | Polls the sequencer, drives the coordinator through `cargo-zisk remote` | the sequencer and the coordinator |
| `zisk-prepare-keys` | One-shot: downloads, verifies and installs the proving keys | the GPU (constant-tree generation), the key volume |

One tag pins coordinator, worker and daemon together. Every ZiSK binary comes
out of the same release tarball, verified against the sha256 pinned in the
Dockerfile before extraction. Nothing from ZiSK is compiled in the image, and
it carries no `snarkjs` or Node.js: the coordinator path never verifies a
wrapped proof locally, and the daemon's `cargo-zisk remote` calls have no
verify flag. The GPU binaries link only the driver's `libcuda.so.1`, which the
NVIDIA container toolkit mounts at run time, so the image sits on plain
Ubuntu rather than a CUDA runtime image. The tarball is x86_64 only, so the
image is `linux/amd64`.

## Proving keys

The STARK key (3.8 GB compressed) and the PLONK key (21.9 GB compressed)
are not in the image. `zisk-prepare-keys`, run as a one-shot service before
the worker, downloads both from Polygon's `zisk-setup` bucket for the
image's ZiSK version, checks the bucket's md5 sidecars and the sha256 pins in
[`keys.sha256`](keys.sha256), extracts them into the key volume, and runs the
same constant-tree generation `ziskup` performs. A marker in the volume makes
later runs a no-op.

Both pins were recorded from full downloads whose md5 matched the sidecars.
When a new ZiSK version rotates the keys, a pin that reads `PENDING` stops
the run unless `ZISK_KEYS_ALLOW_UNPINNED=1` is set, in which case the run
trusts the md5 alone and prints the observed sha256 so it can be recorded
and reviewed. Plan for about 80 GB in the key volume during installation and
40 GB after.

## Running the stack

```bash
cd docker/zisk-stack
cp .env.example .env         # ZISK_SEQUENCER_URL, image tag, GPU index
docker compose up -d         # first start fetches the keys
docker compose logs -f worker prover
```

[`compose.yaml`](compose.yaml) wires the pieces: `prepare-keys` completes,
the worker joins the coordinator on its cluster port, and the daemon
registers both guest ELFs through `cargo-zisk remote setup` and starts
polling the sequencer in aggregated mode. The daemon retries that setup until
a worker has finished loading its keys, which takes several minutes on a
cold start, and re-runs it once whenever a prove fails, so a coordinator
restart heals without restarting the daemon.

Ports on loopback: 7000 (coordinator client API), 9090 (coordinator metrics
and `/health`), 3313 (daemon metrics).

Host requirements: the NVIDIA container toolkit, a GPU with 16 GB or more of
VRAM, 64 GB or more of RAM (the PLONK key stays resident), and disk for the
key volume.

### Worker flags worth knowing

The compose file starts the worker with `--plonk --preload-plonk --gpu
--emulator`. Dropping `--emulator` selects the ASM emulator, which is faster
at witness generation; the image carries the build toolchain it assembles
with, and the compose file already lifts the memlock limit it needs. One
worker serves one GPU; copy the service with another `CUDA_VISIBLE_DEVICES`
for more, all joining the same coordinator.

## Building

```bash
# Developer build: daemon compiled in a container, ELFs from the reproducible builds
docker/zisk-stack/build-images.sh --prover-from-docker

# Release build: the released daemon binary and ELFs, SHA256SUMS-verified,
# so the image carries the exact bytes the release manifest pins
docker/zisk-stack/build-images.sh --prover-from-release 0.0.6 --registry ghcr.io/matter-labs --tag 0.0.6 --push
```

The image copies `out/zksync-os-zisk-guest`, `out/zksync-os-zisk-guest-aggregator`
and `out/zksync-os-zisk-prover-service` from the build context and
re-verifies the ELFs against the recorded `GUEST_ELF_SHA256` pins, so a stale
`out/` cannot ship. The ZiSK binaries come from the pinned toolchain tarball.

CI builds the image on pushes to `main` (`stage-build.yaml`) and publishes
it to GHCR and GAR. On a release, `release-assets.yaml` builds it from the
released assets and publishes it to GHCR, GAR and quay with the release tag.

## Files

| File | Purpose |
|---|---|
| `Dockerfile`, `Dockerfile.dockerignore` | The `stack` target plus the `prover-export` helper |
| `coordinator.toml`, `coordinator-core.toml` | Coordinator service and core config (ports, JSON logs, no proof persistence) |
| `worker.toml` | Worker config; key paths and GPU flags stay on the command line |
| `prepare-keys.sh` | Installed as `zisk-prepare-keys` |
| `keys.sha256` | sha256 pins of the key tarballs |
| `compose.yaml`, `.env.example` | Single-machine deployment |
| `build-images.sh` | Builds the image from a checkout or a release |
