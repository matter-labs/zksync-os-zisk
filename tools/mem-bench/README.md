# mem-bench — guest-memory fix effectiveness harness

Peak-heap benchmark for the two ZiSK guest-memory fixes, baseline (pre-fix code
path) vs fixed, over the **real** library code. Host-runnable only — no GPU, no
guest ELF.

- **Streaming read path (read-spam):** `execute_and_commit_from_bincode` (collecting:
  `bincode::deserialize::<BatchInput>` + `build_proven_db`, all merkle siblings
  resident) vs `execute_and_commit_streaming` (verify-and-drop each proof), over
  N distinct cold storage slots at tree depth D.
- **Streaming tree update (write-spam):** `BatchTreeUpdate::apply_reference` (two-pass reference,
  `O(W·D)` `authenticated` map) vs the streaming `apply` (`O(W)` walk), over W
  writes at tree depth D.

## Metric

Peak heap high-water via a tracking global allocator (sum of live allocation
sizes) — an allocator-independent first-order proxy for the guest dlmalloc wall
(**507.75 MiB**). Wall time is also reported so the memory fix's throughput
impact is visible. The eventual box-side validation is the guest `BUMP_PTR`
high-water under `ziskemu`.

Peak semantics differ per fix (annotated in the output tables):

- Read-path peak **excludes** the serialized witness (it lives in the guest's
  read-only input region, not the heap).
- Tree-update peak **includes** the deserialized `tree_update` witness (which is on
  the heap) plus the algorithm working set.

## Run

```sh
# from this directory
ZKSYNC_USE_CUDA_STUBS=1 cargo run --release -- all --full --out RESULTS.md
```

Arguments:

- `a` | `b` | `all` — which fix to sweep (default `all`).
- `--full` — include the largest measured points (N=100k, W=94,644); omit for a
  quicker run.
- `--out PATH` — also write the markdown tables to `PATH`.

`RESULTS.md` in this directory is a committed snapshot of a `--full` run. The
max-native points (N=283,683 read slots) are linearly extrapolated from the
largest measured N (per-slot cost is constant) and clearly labelled.
