//! Peak-heap benchmark harness for the two ZiSK guest-memory fixes.
//!
//! Read path (read-spam): `bincode::deserialize::<BatchInput>` + `build_proven_db`
//! (via `execute_and_commit_from_bincode`, the collecting path) vs the streaming
//! `execute_and_commit_streaming`, over N distinct cold storage slots at tree
//! depth D.
//!
//! Write path (write-spam): `BatchTreeUpdate::apply_reference` (the two-pass reference
//! with the `O(W·D)` `authenticated` map) vs the streaming `apply` (`O(W)`
//! walk), over W writes at tree depth D.
//!
//! Metric: peak heap high-water via a tracking global allocator (sum of live
//! allocations) — an allocator-independent proxy for the guest dlmalloc wall
//! (507.75 MiB). Also reports wall time so the memory fix's throughput impact is
//! visible. Runs the REAL library code paths (no mocks, no GPU, no guest ELF).
//!
//! Metric semantics per fix (annotated in the tables):
//! * Read-path peak = heap allocated DURING the run, EXCLUDING the serialized
//!   witness bytes (those live in the guest's separate read-only input region,
//!   not the heap).
//! * Write-path peak = the deserialized `tree_update` witness (which IS on the heap)
//!   PLUS the algorithm working set — the true guest-heap figure.
//!
//! Usage:
//!   cargo run --release -- [a|b|all] [--full] [--out PATH]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use alloy_primitives::{Address, B256, U256};
use zksync_os_zisk_lib::merkle::{
    self, BatchTreeUpdate, SlotProofEntry, StorageProof, TreeLeaf, WriteOp,
};
use zksync_os_zisk_lib::types::*;
use zksync_os_zisk_lib::{commitment, executor};

// --------------------------------------------------------------------------
// Tracking global allocator (peak live bytes).
// --------------------------------------------------------------------------

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Tracking;
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        System.dealloc(p, l);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, ns: usize) -> *mut u8 {
        let np = System.realloc(p, l, ns);
        if !np.is_null() {
            if ns >= l.size() {
                let now = LIVE.fetch_add(ns - l.size(), Ordering::Relaxed) + (ns - l.size());
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(l.size() - ns, Ordering::Relaxed);
            }
        }
        np
    }
}

#[global_allocator]
static A: Tracking = Tracking;

const MIB: f64 = 1_048_576.0;
const BUDGET_MIB: f64 = 507.75;

fn mib(b: usize) -> f64 {
    b as f64 / MIB
}

/// Reset the peak to the current live total, run `f`, and return
/// (peak_over_base_bytes, elapsed).
fn measure_over_base<R>(f: impl FnOnce() -> R) -> (usize, Duration) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let t = Instant::now();
    let r = f();
    let dt = t.elapsed();
    let peak = PEAK.load(Ordering::Relaxed);
    drop(r);
    (peak.saturating_sub(base), dt)
}

// --------------------------------------------------------------------------
// Shared dense-tree builder (valid depth-64 proofs).
// --------------------------------------------------------------------------

fn compress(l: &B256, r: &B256) -> B256 {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(l.as_slice());
    b[32..].copy_from_slice(r.as_slice());
    merkle::blake2s(&b)
}

/// Dense tree over MIN/MAX guards + data leaves. Returns (root, leaves by index,
/// per-leaf full 64-length sibling paths).
fn build_dense_tree(data: &[(B256, B256)]) -> (B256, Vec<(u64, TreeLeaf)>, Vec<Vec<B256>>) {
    let mut recs: Vec<(u64, B256, B256)> = vec![
        (0, B256::ZERO, B256::ZERO),
        (1, B256::repeat_byte(0xff), B256::ZERO),
    ];
    for (i, (k, v)) in data.iter().enumerate() {
        recs.push((2 + i as u64, *k, *v));
    }
    let mut order: Vec<usize> = (0..recs.len()).collect();
    order.sort_by(|&a, &b| recs[a].1.cmp(&recs[b].1));
    let mut next = vec![0u64; recs.len()];
    for w in order.windows(2) {
        next[w[0]] = recs[w[1]].0;
    }
    next[*order.last().unwrap()] = 1;

    let leaves: Vec<(u64, TreeLeaf)> = recs
        .iter()
        .zip(&next)
        .map(|((idx, k, v), n)| {
            (
                *idx,
                TreeLeaf {
                    key: *k,
                    value: *v,
                    next_index: *n,
                },
            )
        })
        .collect();

    let mut levels: Vec<Vec<B256>> = vec![leaves
        .iter()
        .map(|(_, l)| merkle::hash_leaf(&l.key, &l.value, l.next_index))
        .collect()];
    while levels.last().unwrap().len() > 1 {
        let d = levels.len() - 1;
        let cur = levels.last().unwrap();
        let nl: Vec<B256> = (0..cur.len().div_ceil(2))
            .map(|i| {
                let l = cur[2 * i];
                let r = cur
                    .get(2 * i + 1)
                    .copied()
                    .unwrap_or(merkle::empty_subtree_hash(d as u8));
                compress(&l, &r)
            })
            .collect();
        levels.push(nl);
    }
    let mut root = levels.last().unwrap()[0];
    for d in (levels.len() - 1)..64 {
        root = compress(&root, &merkle::empty_subtree_hash(d as u8));
    }

    let siblings: Vec<Vec<B256>> = (0..leaves.len() as u64)
        .map(|i| {
            (0..64usize)
                .map(|d| {
                    let pos = ((i >> d) ^ 1) as usize;
                    levels
                        .get(d)
                        .and_then(|lvl| lvl.get(pos).copied())
                        .unwrap_or(merkle::empty_subtree_hash(d as u8))
                })
                .collect()
        })
        .collect();
    (root, leaves, siblings)
}

fn enc_props(nonce: u64, balance: U256) -> Vec<u8> {
    let mut d = vec![0u8; 124];
    d[8..16].copy_from_slice(&nonce.to_be_bytes());
    d[16..48].copy_from_slice(&balance.to_be_bytes::<32>());
    d
}

fn empty_ring_blake() -> B256 {
    commitment::block_hashes_blake(&[B256::ZERO; 255], &B256::ZERO)
}

fn l1_abi(sender: Address, recipient: Address) -> Vec<u8> {
    let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
    abi[31] = 0x20;
    abi[32 + 31] = 0x7f;
    abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice());
    abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice());
    abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes());
    abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
    abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice());
    let dyn_base = 19u32 * 32;
    for j in 0..5u32 {
        let off = 32 + (14 + j as usize) * 32;
        abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
    }
    abi
}

/// Ceil(log2) of the leaf count — the number of non-trivial sibling levels.
fn actual_depth(leaf_count: u64) -> u32 {
    if leaf_count <= 1 {
        0
    } else {
        64 - (leaf_count - 1).leading_zeros()
    }
}

/// Read-spam batch: `n` cold storage slots (valid proofs truncated to `d`
/// siblings) + the sender account, one force_fail L1 tx (execution touches
/// nothing, so the witness dominates). `d` must be >= the tree's natural depth.
fn build_read_spam(n: usize, d: usize) -> BatchInput {
    let sender: Address = "0x1000000000000000000000000000000000000001"
        .parse()
        .unwrap();
    let recipient: Address = "0x2000000000000000000000000000000000000002"
        .parse()
        .unwrap();
    let sender_props = enc_props(0, U256::from(10_000_000_000_000_000_000u128));
    let sender_flat = merkle::derive_account_properties_key(&sender.into_array());

    let mut data: Vec<(B256, B256)> = Vec::with_capacity(n + 1);
    data.push((sender_flat, merkle::AccountProperties::hash(&sender_props)));
    let some_addr = [0x11u8; 20];
    for i in 0..n {
        let mut slot = [0u8; 32];
        slot[24..32].copy_from_slice(&(i as u64).to_be_bytes());
        let fk = merkle::derive_flat_storage_key(&some_addr, &B256::from(slot));
        data.push((fk, B256::repeat_byte((i % 251) as u8 + 1)));
    }
    let (root, leaves, siblings) = build_dense_tree(&data);
    assert!(
        d as u32 >= actual_depth(leaves.len() as u64),
        "requested depth {d} < natural depth {} for n={n}",
        actual_depth(leaves.len() as u64)
    );

    // Truncate every proof's siblings to `d` (levels d..64 are empty subtrees,
    // supplied implicitly by recover_root — the proof still verifies).
    let proof_for = |leaf_idx: usize| -> StorageProof {
        let (idx, leaf) = &leaves[leaf_idx];
        StorageProof::Existing(SlotProofEntry {
            index: *idx,
            value: leaf.value,
            next_index: leaf.next_index,
            siblings: siblings[leaf_idx][..d].to_vec(),
        })
    };
    let mut storage_proofs = Vec::with_capacity(n + 1);
    for (j, (k, _)) in data.iter().enumerate() {
        storage_proofs.push((*k, proof_for(j + 2)));
    }

    let abi = l1_abi(sender, recipient);
    let l1_tx_hash = alloy_primitives::keccak256(&abi);

    BatchInput {
        version: BATCH_INPUT_VERSION,
        chain_id: 270,
        spec_id: 1,
        protocol_version_minor: 30,
        batch_meta: BatchMeta {
            tree_root_before: root,
            leaf_count_before: leaves.len() as u64,
            block_number_before: 0,
            last_block_timestamp_before: 0,
            block_hashes_blake_before: empty_ring_blake(),
            previous_block_hashes: vec![],
            upgrade_tx_hash: B256::ZERO,
            da_commitment_scheme: 2,
            pubdata: vec![],
            multichain_root: B256::ZERO,
            sl_chain_id: 0,
            blob_versioned_hashes: vec![],
            tree_update: None,
            account_preimages_after: vec![],
            fri_proof_verification_enabled: false,
            max_tx_gas_limit: 1 << 24,
            pubdata_content: 0,
            // v30 batch: the output layout commits no interop scalars.
            interop_proofs: None,
        },
        blocks: vec![BlockInput {
            number: 1,
            timestamp: 1_700_000_000,
            base_fee: 250_000_000,
            gas_limit: 80_000_000,
            coinbase: sender,
            prev_randao: B256::from([1u8; 32]),
            block_header_hash: B256::ZERO,
            storage_proofs,
            account_preimages: vec![(sender, sender_props)],
            transactions: vec![TxInput {
                chain_id: Some(270),
                gas_used_override: Some(0),
                force_fail: true,
                auth: TxAuth::L1 {
                    tx_hash: l1_tx_hash,
                    abi_encoded: abi,
                },
            }],
            block_hashes: vec![],
            l2_to_l1_logs: vec![L2ToL1LogEntry {
                l2_shard_id: 0,
                is_service: true,
                tx_number_in_block: 0,
                sender: "0x0000000000000000000000000000000000008001"
                    .parse()
                    .unwrap(),
                key: l1_tx_hash,
                value: B256::ZERO,
            }],
            expected_tree_root: B256::ZERO,
        }],
        bytecodes: vec![],
    }
}

// --------------------------------------------------------------------------
// Tree-update witness: W update writes spread across a depth-D tree.
// --------------------------------------------------------------------------

fn key_of(x: u64) -> B256 {
    let mut b = [0u8; 32];
    b[24..32].copy_from_slice(&x.to_be_bytes());
    B256::from(b)
}

/// Simulate the old-root reconstruction over `touched` (sorted (index, leaf
/// hash)) with every non-present position treated as an empty subtree, mirroring
/// `zip_and_record`. Returns (old_root, intermediate_hashes) — the exact
/// intermediates the reconstruction consumes (all empty-subtree hashes, since
/// the touched leaves are spread apart). O(W·D) time, no 2^D materialisation.
fn simulate_spread(touched: &[(u64, B256)], leaf_count: u64) -> (B256, Vec<B256>) {
    let mut inters = Vec::new();
    let mut nodes: Vec<(u64, B256)> = touched.to_vec();
    let mut last_idx = leaf_count - 1;
    for depth in 0..64usize {
        let empty = merkle::empty_subtree_hash(depth as u8);
        let mut i = 0;
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2) + 1);
        while i < nodes.len() {
            let (cur, h) = nodes[i];
            let parent = if cur % 2 == 1 {
                i += 1;
                inters.push(empty);
                compress(&empty, &h)
            } else if i + 1 < nodes.len() && nodes[i + 1].0 == cur + 1 {
                let rh = nodes[i + 1].1;
                i += 2;
                compress(&h, &rh)
            } else {
                i += 1;
                if cur != last_idx {
                    inters.push(empty);
                }
                compress(&h, &empty)
            };
            next.push((cur / 2, parent));
        }
        nodes = next;
        last_idx /= 2;
    }
    (nodes[0].1, inters)
}

/// Update-only write-spam witness: `w` writes spread across a depth-`d` tree
/// (leaf_count_before = 2^d). Worst case for the reference `authenticated` map
/// (paths stay separate for ~d - log2(w) levels). Returns (update, old_root).
fn build_update_spread(w: u64, d: u32) -> (BatchTreeUpdate, B256) {
    let leaf_count: u64 = 1u64 << d;
    assert!(w >= 1 && w <= leaf_count);
    let stride = leaf_count / w;

    // Touched leaves at spread indices; arbitrary keys/values (update-only, so
    // next_index / linked-list validity is irrelevant to the root).
    let mut sorted_leaves: Vec<(u64, TreeLeaf)> = Vec::with_capacity(w as usize);
    for i in 0..w {
        let idx = i * stride;
        sorted_leaves.push((
            idx,
            TreeLeaf {
                key: key_of(idx.wrapping_mul(2_654_435_761)),
                value: key_of(i),
                next_index: 0,
            },
        ));
    }
    sorted_leaves.sort_by_key(|(idx, _)| *idx);

    let touched: Vec<(u64, B256)> = sorted_leaves
        .iter()
        .map(|(idx, l)| (*idx, merkle::hash_leaf(&l.key, &l.value, l.next_index)))
        .collect();
    let (old_root, intermediate_hashes) = simulate_spread(&touched, leaf_count);

    let operations: Vec<WriteOp> = sorted_leaves
        .iter()
        .map(|(idx, _)| WriteOp::Update { index: *idx })
        .collect();
    let entries: Vec<(B256, B256)> = sorted_leaves
        .iter()
        .enumerate()
        .map(|(n, (_, l))| (l.key, key_of(7_000_000 + n as u64)))
        .collect();

    (
        BatchTreeUpdate {
            operations,
            entries,
            sorted_leaves,
            intermediate_hashes,
            leaf_count_before: leaf_count,
        },
        old_root,
    )
}

// --------------------------------------------------------------------------
// Sweeps.
// --------------------------------------------------------------------------

struct RowA {
    n: usize,
    d: usize,
    ser_mib: f64,
    base_mib: f64,
    fix_mib: f64,
    base_ms: f64,
    fix_ms: f64,
}

fn run_fix_a(ns: &[usize], ds: &[usize]) -> Vec<RowA> {
    let mut rows = Vec::new();
    for &n in ns {
        for &d in ds {
            let input = build_read_spam(n, d);
            let bytes = bincode::serialize(&input).unwrap();
            let ser = bytes.len();
            drop(input); // only the serialized witness (RO region) stays resident

            let (base_peak, base_t) =
                measure_over_base(|| executor::execute_and_commit_from_bincode(&bytes).unwrap());
            let (fix_peak, fix_t) =
                measure_over_base(|| executor::execute_and_commit_streaming(&bytes).unwrap());

            let row = RowA {
                n,
                d,
                ser_mib: mib(ser),
                base_mib: mib(base_peak),
                fix_mib: mib(fix_peak),
                base_ms: base_t.as_secs_f64() * 1e3,
                fix_ms: fix_t.as_secs_f64() * 1e3,
            };
            eprintln!(
                "READ   N={:>7} D={:>2}  ser={:>7.1}  base={:>7.1}  fixed={:>6.2}  ({:.1}x)  t {:.0}/{:.0} ms",
                row.n, row.d, row.ser_mib, row.base_mib, row.fix_mib,
                row.base_mib / row.fix_mib.max(1e-9), row.base_ms, row.fix_ms
            );
            rows.push(row);
        }
    }
    rows
}

struct RowB {
    w: u64,
    d: u32,
    witness_mib: f64,
    base_total_mib: f64,
    fix_total_mib: f64,
    base_ms: f64,
    fix_ms: f64,
}

fn run_fix_b(ws: &[u64], ds: &[u32]) -> Vec<RowB> {
    let mut rows = Vec::new();
    for &w in ws {
        for &d in ds {
            let before = LIVE.load(Ordering::Relaxed);
            let (update, root) = build_update_spread(w, d);
            let witness = LIVE.load(Ordering::Relaxed).saturating_sub(before);

            let (base_marg, base_t) = measure_over_base(|| update.apply_reference(&root));
            let (fix_marg, fix_t) = measure_over_base(|| update.apply(&root));
            drop(update);

            let row = RowB {
                w,
                d,
                witness_mib: mib(witness),
                base_total_mib: mib(witness + base_marg),
                fix_total_mib: mib(witness + fix_marg),
                base_ms: base_t.as_secs_f64() * 1e3,
                fix_ms: fix_t.as_secs_f64() * 1e3,
            };
            eprintln!(
                "WRITE  W={:>7} D={:>2}  witness={:>6.1}  base={:>7.1}  fixed={:>6.1}  ({:.1}x)  t {:.0}/{:.0} ms",
                row.w, row.d, row.witness_mib, row.base_total_mib, row.fix_total_mib,
                row.base_total_mib / row.fix_total_mib.max(1e-9), row.base_ms, row.fix_ms
            );
            rows.push(row);
        }
    }
    rows
}

fn under(v: f64) -> &'static str {
    if v < BUDGET_MIB {
        "yes"
    } else {
        "**NO (OOM)**"
    }
}

fn markdown(rows_a: &[RowA], rows_b: &[RowB], max_n: usize) -> String {
    let mut s = String::new();
    s.push_str("# Guest-memory fix effectiveness (peak-heap benchmark)\n\n");
    s.push_str(&format!(
        "Tracking-allocator peak-live-bytes proxy for the guest dlmalloc wall \
         (**{BUDGET_MIB} MiB**). Baseline = current/pre-fix code path; fixed = \
         streaming path. Real library code, host-runnable (CUDA stubs, no GPU / \
         guest ELF). `BUMP_PTR` emulator confirmation is the eventual box-side \
         validation.\n\n"
    ));

    // ---- read path ----
    s.push_str("## Streaming storage-proof deserialize (read-spam)\n\n");
    s.push_str(
        "Peak = heap allocated during deserialize + `build_proven_db` + trivial \
         (force_fail) execution, **excluding** the serialized witness (which lives \
         in the guest's read-only input region, not the heap). Baseline = \
         `execute_and_commit_from_bincode`; fixed = `execute_and_commit_streaming`. \
         `serialized` is the wire witness size (informational).\n\n",
    );
    s.push_str("| N slots | depth D | serialized MiB | peak_baseline MiB | peak_fixed MiB | reduction× | baseline <508? | fixed <508? |\n");
    s.push_str("|--:|--:|--:|--:|--:|--:|:-:|:-:|\n");
    for r in rows_a {
        s.push_str(&format!(
            "| {} | {} | {:.1} | {:.1} | {:.2} | {:.1}× | {} | {} |\n",
            r.n,
            r.d,
            r.ser_mib,
            r.base_mib,
            r.fix_mib,
            r.base_mib / r.fix_mib.max(1e-9),
            under(r.base_mib),
            under(r.fix_mib),
        ));
    }
    // Linear extrapolation to the max-native read count.
    s.push_str(&extrapolate_a(rows_a, max_n, 283_683));
    s.push('\n');

    // ---- write path ----
    s.push_str("## Streaming O(W) tree update (write-spam)\n\n");
    s.push_str(
        "Peak = the deserialized `tree_update` witness (**on the heap**) PLUS the \
         algorithm working set. Baseline = `apply_reference` (pre-fix two-pass, \
         `O(W·D)` `authenticated` map); fixed = streaming `apply` (`O(W)` walk). \
         W update writes spread across a depth-D tree (worst case for the map). \
         `witness` (the shared `intermediate_hashes`/`sorted_leaves` term) is \
         informational.\n\n",
    );
    s.push_str("| W writes | depth D | witness MiB | peak_baseline MiB | peak_fixed MiB | reduction× | baseline <508? | fixed <508? |\n");
    s.push_str("|--:|--:|--:|--:|--:|--:|:-:|:-:|\n");
    for r in rows_b {
        s.push_str(&format!(
            "| {} | {} | {:.1} | {:.1} | {:.1} | {:.1}× | {} | {} |\n",
            r.w,
            r.d,
            r.witness_mib,
            r.base_total_mib,
            r.fix_total_mib,
            r.base_total_mib / r.fix_total_mib.max(1e-9),
            under(r.base_total_mib),
            under(r.fix_total_mib),
        ));
    }
    s.push_str(&extrapolate_b(rows_b, 94_644));
    s.push('\n');
    s
}

/// Linearly extrapolate the max-native read-spam row (283,683 slots) from the
/// largest measured N at each depth (per-slot cost is constant).
fn extrapolate_a(rows: &[RowA], measured_max_n: usize, target_n: usize) -> String {
    let mut s = String::new();
    if target_n <= measured_max_n {
        return s;
    }
    s.push_str(&format!(
        "\n_Extrapolated to the max-native read count (N={target_n}) from the \
         N={measured_max_n} rows (peak scales linearly in N):_\n\n"
    ));
    s.push_str("| N slots | depth D | peak_baseline MiB | peak_fixed MiB | reduction× | baseline <508? | fixed <508? |\n");
    s.push_str("|--:|--:|--:|--:|--:|:-:|:-:|\n");
    let factor = target_n as f64 / measured_max_n as f64;
    for r in rows.iter().filter(|r| r.n == measured_max_n) {
        let b = r.base_mib * factor;
        let f = r.fix_mib * factor;
        s.push_str(&format!(
            "| {} _(extrap)_ | {} | {:.1} | {:.2} | {:.1}× | {} | {} |\n",
            target_n,
            r.d,
            b,
            f,
            b / f.max(1e-9),
            under(b),
            under(f),
        ));
    }
    s
}

/// Note the max-native new-write count relative to the measured W rows.
fn extrapolate_b(rows: &[RowB], target_w: u64) -> String {
    let measured_max = rows.iter().map(|r| r.w).max().unwrap_or(0);
    if target_w <= measured_max {
        return String::new();
    }
    let mut s = String::new();
    s.push_str(&format!(
        "\n_Extrapolated to the max-native new-write count (W={target_w}) from the \
         W={measured_max} rows (both peaks scale ~linearly in W):_\n\n"
    ));
    s.push_str("| W writes | depth D | peak_baseline MiB | peak_fixed MiB | reduction× | baseline <508? | fixed <508? |\n");
    s.push_str("|--:|--:|--:|--:|--:|:-:|:-:|\n");
    let factor = target_w as f64 / measured_max as f64;
    for r in rows.iter().filter(|r| r.w == measured_max) {
        let b = r.base_total_mib * factor;
        let f = r.fix_total_mib * factor;
        s.push_str(&format!(
            "| {} _(extrap)_ | {} | {:.1} | {:.1} | {:.1}× | {} | {} |\n",
            target_w,
            r.d,
            b,
            f,
            b / f.max(1e-9),
            under(b),
            under(f),
        ));
    }
    s
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let which = args.get(1).map(|s| s.as_str()).unwrap_or("all");
    let full = args.iter().any(|a| a == "--full");
    let out = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Sweep points. Read-spam: N × D. Depths must be >= natural depth
    // (~19 for the largest N), so all D ∈ {20,40,55,64} are valid.
    let ns: Vec<usize> = if full {
        vec![1_000, 10_000, 50_000, 100_000]
    } else {
        vec![1_000, 10_000, 50_000]
    };
    let ds_a: Vec<usize> = vec![20, 40, 55, 64];
    let measured_max_n = *ns.iter().max().unwrap();

    // Write-spam: W × D.
    let ws: Vec<u64> = if full {
        vec![1_000, 10_000, 50_000, 94_644]
    } else {
        vec![1_000, 10_000, 50_000]
    };
    let ds_b: Vec<u32> = vec![20, 40, 55];

    let rows_a = if which == "b" {
        Vec::new()
    } else {
        run_fix_a(&ns, &ds_a)
    };
    let rows_b = if which == "a" {
        Vec::new()
    } else {
        run_fix_b(&ws, &ds_b)
    };

    let md = markdown(&rows_a, &rows_b, measured_max_n);
    println!("\n{md}");
    if let Some(path) = out {
        std::fs::write(&path, &md).expect("write results file");
        eprintln!("wrote {path}");
    }
}
