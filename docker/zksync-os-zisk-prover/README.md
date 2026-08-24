# zksync-os-zisk-prover image

Production image for the ZiSK prover daemon
([`prover/`](../../prover/README.md)). It contains:

- `zksync-os-zisk-prover-service` at `/usr/local/bin/`
- the two hash-verified guest ELFs at `/app/elf/zksync-os-zisk-guest` and
  `/app/elf/zksync-os-zisk-guest-aggregator`, checked against the recorded
  `GUEST_ELF_SHA256` values during the image build
- the ZiSK v0.18.0 GPU toolchain (`cargo-zisk`, `ziskemu`, `zisk-coordinator`,
  `zisk-worker`) at `/opt/zisk/bin`, installed with `ziskup --system --gpu --nokey`

The base is a CUDA runtime image, so the container needs the NVIDIA container
toolkit and `--gpus all` (16 GB+ VRAM; see the machine requirements in
[`E2E_SETUP.md`](../../E2E_SETUP.md)).

## Building

Build from the repo root **after** the reproducible guest builds have
populated `out/` (they verify the ELFs against the recorded hashes and fail
on mismatch; the Dockerfile re-verifies the copies):

```bash
./build-guest.sh && ./build-aggregator.sh
docker build -f docker/zksync-os-zisk-prover/Dockerfile -t zksync-os-zisk-prover .
```

CI builds and pushes the image via `.github/workflows/stage-build.yaml`.

## Proving keys arrive at runtime

The STARK + PLONK proving keys are ~26–40 GB, so they are **not** baked into
the image (unlike the airbender image's CRS file). Two options:

**1. Mounted volume (recommended).** Download the keys once on the host —
`ziskup -v 0.18.0 --provingkey --gpu` for the STARK key plus
`ziskup setup_snark` for the PLONK key (they land in `~/.zisk/provingKey` and
`~/.zisk/provingKeySnark`) — and mount them:

```bash
docker run --gpus all \
  -v ~/.zisk/provingKey:/opt/zisk/provingKey:ro \
  -v ~/.zisk/provingKeySnark:/opt/zisk/provingKeySnark:ro \
  zksync-os-zisk-prover \
  --sequencer-url http://sequencer:3124 \
  --zisk-binary /opt/zisk/bin/cargo-zisk \
  --elf-path /app/elf/zksync-os-zisk-guest \
  --aggregation --aggregator-elf /app/elf/zksync-os-zisk-guest-aggregator \
  --proving-key /opt/zisk/provingKey \
  --proving-key-plonk /opt/zisk/provingKeySnark
```

**2. ziskup inside the container.** The image keeps `ziskup` installed; with a
persistent volume mounted at `/opt/zisk` the download happens once:

```bash
ziskup -v 0.18.0 --system --prefix /opt/zisk --gpu --provingkey -y
ziskup -v 0.18.0 --system --prefix /opt/zisk --gpu --provingkey --with-snark -y
```

The daemon defaults to the standard emulator, which runs under the default
container memlock limit; the faster ASM emulator (`--asm-emulator`) needs
`--ulimit memlock=-1`. Prometheus metrics are served on port 3313.

Under `--coordinator-url` (resident prover backend) the keys and the GPU move
to the `zisk-worker`, and this container needs neither — see
[`prover/README.md`](../../prover/README.md).
