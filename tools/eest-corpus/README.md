# Committed EEST native-reference corpus

This directory contains content-addressed ZKsync OS state dumps generated from
EEST v5.4.0. Each dump carries the complete witness plus the commitments emitted
by native ZKsync OS. Pull-request CI rebuilds `dump_to_batchinput` from the
candidate branch and checks every unique dump against those native references.

The corpus is sharded by EEST family. `manifest.json` pins the fixture version,
the state-dump producer commit, source and deduplicated case counts, compressed
sizes, and SHA-256 for every archive. A case file is named by the SHA-256 of its
canonical JSON. Object keys and semantically unordered witness collections are
sorted, removing superficial serialization ordering. Case identity derives
from the canonical payload rather than the producer's parallel case counter.
`skipped_filters` records fixture families the pinned producer cannot parse or
execute, so the committed coverage boundary stays explicit.

The per-PR corpus covers the established 35-family baseline from the ZKsync OS
v0.5.4-private release at protocol minor 32. It contains 33 nonempty shards; the
manifest records two filters that emit no dump and the separate
`static/state_tests` is listed as excluded because its native producer includes
pathological long-running cases; it remains a separate resource-bounded run.

Run the committed gate locally:

```bash
cargo build --release --manifest-path tools/test-utils/Cargo.toml \
  --bin dump_to_batchinput
tools/run-eest-native.py \
  --reader tools/test-utils/target/release/dump_to_batchinput \
  --output /tmp/zisk-eest-native
```

Regeneration needs a clean dedicated checkout of `matter-labs/zksync-os` at the
`v0.5.4-private` tag and commit recorded in the generator, plus the official
EEST v5.4.0 stable and develop fixtures. This release's state-dump hook exports
the per-transaction revert flag consumed by the fixture conversion; the
regenerated corpus contains 1,272 transactions with that flag set. Its
`evm-tester` manifest selects the Ethereum-conformance feature, so the
generator applies the checked-in one-line
`tools/eest-v0.5.4-private-production-rig.patch`; the manifest records its
SHA-256 so the source plus the exact build transformation remain reproducible.

```bash
CARGO_TARGET_DIR=/path/to/fresh-target \
CORPUS_BUILD_DIR=/path/to/large-temporary-directory \
tools/generate-eest-corpus.sh \
  /path/to/dedicated-zksync-os-checkout \
  /path/to/ethereum-fixtures \
  /path/to/empty-corpus-output
```

Regenerate only when the native protocol reference or fixture release changes.
Review manifest counts and hashes, run the full native gate, and land the corpus
rotation together with any required waiver changes. Target-specific ZiSK ABI and
crypto-hook coverage remains in the separate `ziskemu` lane.

The native producer can assign equivalent internal witness layouts in different
orders across executions. Canonicalization removes output-order differences but
does not rewrite tree indices or other semantic witness fields. Treat regenerated
shard and dedup-count changes as reviewable data changes; the manifest and
content-addressed filenames make the exact committed baseline unambiguous.
