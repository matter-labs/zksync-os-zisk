# Guest-memory fix effectiveness (peak-heap benchmark)

Tracking-allocator peak-live-bytes proxy for the guest dlmalloc wall (**507.75 MiB**). Baseline = current/pre-fix code path; fixed = streaming path. Real library code, host-runnable (CUDA stubs, no GPU / guest ELF). `BUMP_PTR` emulator confirmation is the eventual box-side validation.

## Streaming storage-proof deserialize (read-spam)

Peak = heap allocated during deserialize + `build_proven_db` + trivial (force_fail) execution, **excluding** the serialized witness (which lives in the guest's read-only input region, not the heap). Baseline = `execute_and_commit_from_bincode`; fixed = `execute_and_commit_streaming`. `serialized` is the wire witness size (informational).

| N slots | depth D | serialized MiB | peak_baseline MiB | peak_fixed MiB | reduction× | baseline <508? | fixed <508? |
|--:|--:|--:|--:|--:|--:|:-:|:-:|
| 1000 | 20 | 0.9 | 1.0 | 0.20 | 5.3× | yes | yes |
| 1000 | 40 | 1.6 | 1.6 | 0.20 | 8.4× | yes | yes |
| 1000 | 55 | 2.2 | 2.1 | 0.20 | 10.7× | yes | yes |
| 1000 | 64 | 2.5 | 2.4 | 0.20 | 12.1× | yes | yes |
| 10000 | 20 | 8.7 | 11.7 | 1.55 | 7.5× | yes | yes |
| 10000 | 40 | 16.3 | 17.8 | 1.55 | 11.5× | yes | yes |
| 10000 | 55 | 22.0 | 22.3 | 1.55 | 14.4× | yes | yes |
| 10000 | 64 | 25.4 | 25.1 | 1.55 | 16.2× | yes | yes |
| 50000 | 20 | 43.3 | 52.7 | 6.19 | 8.5× | yes | yes |
| 50000 | 40 | 81.4 | 83.2 | 6.19 | 13.4× | yes | yes |
| 50000 | 55 | 110.1 | 106.1 | 6.19 | 17.1× | yes | yes |
| 50000 | 64 | 127.2 | 119.8 | 6.19 | 19.4× | yes | yes |
| 100000 | 20 | 86.6 | 105.4 | 12.38 | 8.5× | yes | yes |
| 100000 | 40 | 162.9 | 166.4 | 12.38 | 13.4× | yes | yes |
| 100000 | 55 | 220.1 | 212.2 | 12.38 | 17.1× | yes | yes |
| 100000 | 64 | 254.4 | 239.7 | 12.38 | 19.4× | yes | yes |

_Extrapolated to the max-native read count (N=283683) from the N=100000 rows (peak scales linearly in N):_

| N slots | depth D | peak_baseline MiB | peak_fixed MiB | reduction× | baseline <508? | fixed <508? |
|--:|--:|--:|--:|--:|:-:|:-:|
| 283683 _(extrap)_ | 20 | 299.0 | 35.11 | 8.5× | yes | yes |
| 283683 _(extrap)_ | 40 | 472.2 | 35.11 | 13.4× | yes | yes |
| 283683 _(extrap)_ | 55 | 602.0 | 35.11 | 17.1× | **NO (OOM)** | yes |
| 283683 _(extrap)_ | 64 | 680.0 | 35.12 | 19.4× | **NO (OOM)** | yes |

## Streaming O(W) tree update (write-spam)

Peak = the deserialized `tree_update` witness (**on the heap**) PLUS the algorithm working set. Baseline = `apply_reference` (pre-fix two-pass, `O(W·D)` `authenticated` map); fixed = streaming `apply` (`O(W)` walk). W update writes spread across a depth-D tree (worst case for the map). `witness` (the shared `intermediate_hashes`/`sorted_leaves` term) is informational.

| W writes | depth D | witness MiB | peak_baseline MiB | peak_fixed MiB | reduction× | baseline <508? | fixed <508? |
|--:|--:|--:|--:|--:|--:|:-:|:-:|
| 1000 | 20 | 0.7 | 3.0 | 0.9 | 3.3× | yes | yes |
| 1000 | 40 | 1.2 | 10.4 | 1.4 | 7.4× | yes | yes |
| 1000 | 55 | 2.2 | 11.4 | 2.4 | 4.7× | yes | yes |
| 10000 | 20 | 5.5 | 24.3 | 7.9 | 3.1× | yes | yes |
| 10000 | 40 | 17.5 | 91.4 | 19.9 | 4.6× | yes | yes |
| 10000 | 55 | 17.5 | 91.4 | 19.9 | 4.6× | yes | yes |
| 50000 | 20 | 15.6 | 91.0 | 27.4 | 3.3× | yes | yes |
| 50000 | 40 | 71.6 | 367.5 | 83.4 | 4.4× | yes | yes |
| 50000 | 55 | 71.6 | 661.5 | 83.4 | 7.9× | **NO (OOM)** | yes |
| 94644 | 20 | 30.4 | 107.6 | 52.8 | 2.0× | yes | yes |
| 94644 | 40 | 142.4 | 734.1 | 164.8 | 4.5× | **NO (OOM)** | yes |
| 94644 | 55 | 142.4 | 1322.1 | 164.8 | 8.0× | **NO (OOM)** | yes |

