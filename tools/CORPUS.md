# EVM-corpus native and target lanes

Runs the ethereum/execution-spec-tests corpus through production-semantics
zksync-os, converts every executed block into a current-wire `BatchInput`, checks
the ZiSK/REVM guest against native ground truth on six axes (header hash,
tree root, state commitments, per-account after-images), and executes each
case in `ziskemu` with the pinned guest ELF.

**Steady state** (established 2026-08-07 against the 0.3.0/v31 line,
guest ELF `0222b690…`):
10,362 cases → 10,336 OK, 0 panics, 26 waived (`corpus-waivers.tsv`).
`corpus-emu.sh` exits 0 exactly when a run reproduces this: only documented
waivers remain. Any other outcome is a regression or a new finding. The count
spans 35 of the 36 chunks; `static_state_tests` needs a run of its own (see
**Known sharp edges**).

## Pull-request native gate

The 35-family baseline is committed under `tools/eest-corpus/` as 33 nonempty
content-addressed shards plus two filters that emit no state dump; the manifest
also records the separate `static/state_tests` exclusion. It preserves 10,605
source cases as 10,605 unique canonical state transitions. The candidate branch
replays every transition through
`dump_to_batchinput` on each pull request:

```text
10,605 unique cases → 10,589 pass, 16 waivers, 0 unexpected
```

The manifest pins EEST v5.4.0, the native state-dump producer commit, case
counts, compressed sizes, and each shard's SHA-256. Canonicalization sorts JSON
object keys, leaves by tree index, and preimages by hash; exact duplicate native
transitions in the committed dataset run once. `corpus-waivers.tsv` remains the
bounded allowlist. Producer witness insertion order can affect regenerated
shards, so corpus rotations require manifest and data review.

The committed producer is the official `matter-labs/zksync-os` v0.5.0 tag at
protocol minor 32. That release contains the state-dump hook and its production
rig feature, but the `evm-tester` manifest selects Ethereum-conformance tester
semantics. The generator applies the committed one-line build overlay recorded
in the manifest to select the tag's existing `production` feature. No fork or
unreachable commit is needed, and the exact source transformation is reviewable.

With a prebuilt reader, the full replay took 14.3 seconds at eight-way
parallelism during local validation. PR CI also builds the reader from the
candidate branch. It requires neither a second repository checkout nor the
13 GB fixture tree.

`static/state_tests` remains an explicit exclusion because native reference
generation contains pathological long-running cases. The target-emulation lane
also stays separate: native replay cannot test the ZiSK entrypoint, fcall ABI,
target memory behavior, or target crypto hooks.

This ZKsync OS 0.5.0 baseline runs against the guest ELF recorded in
`guest/GUEST_ELF_SHA256`. Its steady
state over the 35 chunks is 10,605 cases →
10,589 OK, 0 unexpected, and the same two waiver families the 0.4.0 line
carries. Its `prague/eip2537_bls_12_381_precompiles` chunk stands at 2,008
cases → 2,008 OK, 0 panics, 0 waived.

The sweep exercises the two derivations that run on every batch: the
four-word `chain_config_hash`, checked against the bundle's
`native_chain_config_hash`, and the height-3 chain batch root, which folds
with zero interop commitment tree roots. It does **not** reach the paths that
need chain state the EEST fixtures never build:

- a non-zero interop commitment tree root, so the creation-timestamp word in
  the interop roots rolling hash stays unexercised;
- an interop leaf insertion, so the `0x7004` hook and its L2->L1 log stay
  unexercised;
- `PubdataContent::LogsOnly`, because the dump rig configures full pubdata
  only and the state-dump hook exports no `pubdata_content` field, so the
  chain-config word is covered at mode 0 alone.

Unit tests in `lib/` cover those three, so extend them there rather than
reading a green sweep as full coverage of the 0.5.0 semantics.

## Architecture

```
EEST fixtures ──▶ evm_tester (zksync-os with the state-dump hook,
                  ZKOS_STATE_DUMP_DIR set, production-semantics build)
                  ──▶ one JSON bundle per executed block
                  └──▶ canonical committed shards ──▶ PR native replay
bundle ──▶ dump_to_batchinput (tools/test-utils/, this repo)
           ──▶ BatchInput bincode + framed input.bin, validated vs native
input.bin ──▶ ziskemu + guest ELF ──▶ clean exit or attributed panic
```

The bundle-to-`BatchInput` conversion and the native cross-check live in the
`tools/test-utils` crate library. `dump_to_batchinput` is a thin binary over
it, and `tools/zisk-divergence-validator` calls the same code on scenarios it
runs through the rig itself, so both lanes report on one comparison.

## From-scratch setup

1. **zksync-os checkout** — create a clean dedicated worktree at the official
   `matter-labs/zksync-os` `v0.5.0` tag and pinned commit recorded in the
   manifest. The release hook is env-gated by `ZKOS_STATE_DUMP_DIR` and emits one
   self-contained JSON bundle per executed block: pre/post state (leaves +
   preimages + roots), signed txs with per-tx `failed` markers, block context,
   the full native header, and the mid-chain fields (`block_number_before`,
   `last_block_timestamp_before`, `block_hash_ring_head`).
2. **Production-semantics tester build** — corpus dumps must reflect
   production execution semantics. `generate-eest-corpus.sh` applies
   `tools/eest-v0.5.0-production-rig.patch`, replacing the tester dependency's
   `evm_tester` feature with the release's existing `production` feature. This
   drops base-fee burn, disabled system contracts, mocked `prevrandao`, and
   EIP-4844 tester behavior while retaining the rig's default test harness.
   Fixture verdict FAILs under these semantics are expected; only executed
   blocks and their dumps matter.
3. **Fixtures** — in `tests/evm_tester/` run `./download_ethereum_fixtures.sh`
   (EEST v5.4.0, ~13 GB unpacked, ~250 MB download).
4. **ZiSK v1.2.0-alpha toolchain** — release tarball
   `cargo_zisk_linux_amd64.tar.gz` from the zisk v1.2.0-alpha GitHub release
   into `~/.zisk-1.2.0-alpha/`. On machines without root, extract the runtime libs
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
   `CORPUS_OUT`, `CARGO_TARGET_DIR`, `EMU_JOBS`, `OK_MIN_PERCENT`.

## Running

```bash
# Every committed native-reference transition (the PR gate)
cargo build --release --manifest-path tools/test-utils/Cargo.toml \
  --bin dump_to_batchinput
tools/run-eest-native.py \
  --reader tools/test-utils/target/release/dump_to_batchinput \
  --output /tmp/zisk-eest-native

# Fixture regeneration plus target emulation
tools/corpus-emu.sh --all                       # full suite (36 chunks)
tools/corpus-emu.sh istanbul/eip152_blake2 ...  # targeted families
```

- Chunks are resumable: a chunk with an existing results file is skipped;
  delete `$CORPUS_OUT/chunks/<chunk>.tsv` to re-run it.
- The run ends with a waiver reconciliation against `corpus-waivers.tsv`
  and an emulation-coverage check; exit 0 means steady state reproduced.
- Coverage holds the OK share to `OK_MIN_PERCENT` (default 90). The waiver
  reconciliation counts guest panics, so a run whose reader rejected every
  case reports zero panics with every row waived — total failure that reads
  as success. The floor is what makes such a run fail.
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
- ziskos/toolchain bumps: the accelerated crypto hooks change with them.
  Re-run the p256 and eip2537 families, which carry the inputs the hooks
  handle least like the reference.
- At each protocol bump: regenerate from the matching official native release;
  header roots, fee rules, precompiles, or wire semantics may require a fresh
  divergence-triage round.

## Known sharp edges

- `static_state_tests` holds 36,930 dumped cases, 3.5 times the rest of the
  corpus, and its evm_tester log grows to about 118 GB and fills the volume.
  Give that chunk its own run, discard the tester log, and budget about
  twelve hours of emulation.
- The corpus native build must apply the committed production-rig overlay.
  The stock `evm_tester` feature enables Ethereum-conformance semantics
  (base-fee burn, disabled system contracts, mocked `prevrandao`, and EIP-4844)
  and makes its dumps diverge from the guest.
- The runner force-enables all evm_tester index entries (worktree-local
  sed); fixture verdict FAILs under production semantics are expected and
  irrelevant — only executed blocks and their dumps matter.
- v0.3.0-line bundles report `chain_config_max_tx_gas_limit: 0` (that forward
  path has no ChainConfig). The reader substitutes a non-binding cap, so the
  guest's `min(block_gas_limit, max_tx_gas_limit)` bound reduces to the block
  gas limit — the bound native applies as well. A smaller substitute would
  reject transactions native executed, which the fixtures do send: EEST blocks
  routinely carry a 120,000,000 gas limit.
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
