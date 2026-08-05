# EVM-corpus target-emulation lane

Runs the ethereum/execution-spec-tests corpus through production-semantics
zksync-os, converts every executed block into a wire-v2 `BatchInput`, checks
the ZiSK/REVM guest against native ground truth on six axes (header hash,
tree root, state commitments, per-account after-images), and executes each
case in `ziskemu` with the pinned guest ELF.

**Steady state** (established 2026-07-12 against the 0.3.0/v31 line,
guest ELF `7cb3289f…`):
10,369 cases → 10,336 OK, 0 panics, 26 waived (`corpus-waivers.tsv`).
`corpus-emu.sh` exits 0 exactly when a run reproduces this: only documented
waivers remain. Any other outcome is a regression or a new finding.

That baseline predates the current ELF pin in `guest/GUEST_ELF_SHA256`. Run
the suite again against the current ELF to re-establish steady state (see
**When to re-run** below).

## Architecture

```
EEST fixtures ──▶ evm_tester (zksync-os with the state-dump hook,
                  ZKOS_STATE_DUMP_DIR set, production-semantics build)
                  ──▶ one JSON bundle per executed block
bundle ──▶ dump_to_batchinput (tools/test-utils/, this repo)
           ──▶ BatchInput bincode + framed input.bin, validated vs native
input.bin ──▶ ziskemu + guest ELF ──▶ clean exit or attributed panic
```

## From-scratch setup

1. **zksync-os checkout** — clone `matter-labs/zksync-os`, branch
   `draft-0.4.0`, which carries the rig state-dump hook (env-gated by
   `ZKOS_STATE_DUMP_DIR`; a strict no-op when unset). The hook emits one
   self-contained JSON bundle per executed block: pre/post state (leaves +
   preimages + roots), signed txs with per-tx `failed` markers, block
   context, the full native header, and the mid-chain fields
   (`block_number_before`, `last_block_timestamp_before`,
   `block_hash_ring_head`).
2. **Production-semantics tester build** — corpus dumps must reflect
   production execution semantics, so build `evm-tester` with the
   `evm_tester_prod` feature set. It (a) excludes Ethereum-conformance
   emulation — no base-fee burn, no mocked precompiles, no blob-tx parsing
   beyond what production enables — and (b) keeps only the harness-required
   testing features. `forward_system/evm_tester_prod` expands to
   `production` + `basic_bootloader/resources_for_tester` +
   `unlimited_native`, and `tests/evm_tester` depends on
   `rig` with that feature. Fixture verdict FAILs under these semantics are
   expected; only executed blocks and their dumps matter.
3. **Fixtures** — in `tests/evm_tester/` run `./download_ethereum_fixtures.sh`
   (EEST v5.4.0, ~13 GB unpacked, ~250 MB download).
4. **ZiSK v0.18.0 toolchain** — release tarball
   `cargo_zisk_linux_amd64.tar.gz` from the zisk v0.18.0 GitHub release into
   `~/.zisk-0.18.0/`. On machines without root, extract the runtime libs
   from Ubuntu debs (`libomp5-18`, `libopenmpi3`, `libhwloc15`,
   `libevent-core/pthreads`) via `dpkg -x` into a user dir and export it as
   `LD_LIBRARY_PATH` (the runner's default points at
   `~/.local/zisk-libs/...`). Emulation needs no proving keys.
5. **Guest ELF** — reproducible container build via `./build-guest.sh` in
   this repo (must match `guest/GUEST_ELF_SHA256`), or use a verified copy
   at `out/zksync-os-zisk-guest`.
6. **Environment overrides** — every location the runner uses is an env var
   (see the header of `corpus-emu.sh`): `ZKOS_DUMP_WORKTREE`,
   `ZKOS_FIXTURES`, `ZISK_TESTUTILS_DIR`, `ZISK_GUEST_ELF`, `ZISKEMU`,
   `CORPUS_OUT`, `CARGO_TARGET_DIR`, `EMU_JOBS`.

## Running

```bash
tools/corpus-emu.sh --all                       # full suite (36 chunks)
tools/corpus-emu.sh istanbul/eip152_blake2 ...  # targeted families
```

- Chunks are resumable: a chunk with an existing results file is skipped;
  delete `$CORPUS_OUT/chunks/<chunk>.tsv` to re-run it.
- The run ends with a waiver reconciliation against `corpus-waivers.tsv`;
  exit 0 means steady state reproduced.
- A quick post-bump sanity pass: run three or four small families
  (`istanbul/eip1344_chainid byzantium/eip196_ec_add_mul
  cancun/eip1153_tstore`) before committing to `--all`.

## Resource model (sized for a 30 GB workstation)

Each `ziskemu` peaks at ~7 GB RSS; the runner derives its emulator
parallelism from *available memory* (never core count) and hard-caps every
process (`ulimit -v`), so a pathological input dies alone. evm_tester runs
at 4 threads, niced. A full `--all` pass takes several hours at 2-wide
emulation; on a large-memory box, export `EMU_JOBS` accordingly and it
scales linearly.

## Interpreting results

`$CORPUS_OUT/chunks/<chunk>.tsv` columns: chunk, case, reader status,
emulation status, detail.

- **OK** — guest and production-native agree end-to-end AND the case
  executes cleanly on-target.
- **reader FAIL / SKIPPED** — the guest's host-side re-execution diverged
  from native ground truth (consensus divergence) or the bundle could not be
  converted; the dump + reader log are retained under `$CORPUS_OUT/failed/`.
- **emulation PANIC** — target-only failure (unwired hook, resource
  exhaustion, target-vs-host crypto disagreement). The panic message names
  the site; guest stub lines identify missing precompiles.
- **Waived** — matches `corpus-waivers.tsv` (chunk + signature + bounded
  count). The 26 waived bundles are archived under
  `corpus-waived-fixtures/` (gzipped) so each waiver stays reproducible;
  the waiver manifest entries carry the unreachability arguments.

## When to re-run

- Any guest, lib, or zksync-os-revm change (the guest ELF pin rotates).
- Any zksync-os pin/branch move — and after protocol upgrades, alongside
  testnet replays.
- ziskos/toolchain bumps: the guest's x=0 P-256 tripwire test signals when
  that workaround can be dropped (the underlying hint bug is fixed on the
  ZiSK 1.0 line); re-run the p256 family then.
- At the AtlasV4/0.4.0 guest bump: re-establish steady state against the
  0.4.0 line — its semantics drift from v31 (blake2s-merkle header
  tx/receipt roots, Pectra fee/precompile semantics), so expect a fresh
  divergence-triage round and re-visit the blake2f/KZG/bls stub coverage
  question.

## Known sharp edges

- The corpus native build must use the `evm_tester_prod` feature set
  (production fee/precompile semantics). The stock `evm_tester` features
  emulate Ethereum semantics (base-fee burn, mocked precompiles) and make
  every dump diverge from the guest.
- The runner force-enables all evm_tester index entries (worktree-local
  sed); fixture verdict FAILs under production semantics are expected and
  irrelevant — only executed blocks and their dumps matter.
- Bundles are self-contained per block, including mid-chain fields
  (`block_number_before`, `last_block_timestamp_before`,
  `block_hash_ring_head` — the last is essential at block ≥ 257, the ring
  head is not derivable from the 255 dumped hashes).
- A panicking guest in `ziskemu` runs to the step ceiling
  (`EmulationNoCompleted`, minutes); the runner's emu step cap keeps this
  bounded.
- evm_tester `-p` filters match test identifiers without the channel
  prefix: use `<fork>/<family>` (e.g. `istanbul/eip152_blake2`), which
  covers stable and develop at once.
