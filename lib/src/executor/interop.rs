//! Independent, in-guest authentication of the interop-derived batch scalars.
//!
//! Native zksync-os does NOT take `multichain_root` and `sl_chain_id` from the
//! batch's own logs or dependency roots — it reads them, at batch boundaries, as
//! authenticated storage reads of fixed system-contract slots
//! (`basic_bootloader block_flow/zk/post_tx_op::read_batch_context_inputs`):
//!
//! - `sl_chain_id`  ← SystemContext (`0x800b`) slot 0. Read at POST-batch state
//!   (`tree_root_after`), the batch boundary native reads it at. An upgrade batch
//!   may write this slot during the batch; reading at post-state observes the new
//!   value, so the derivation is authenticated for every batch, including upgrades.
//! - `multichain_root` ← MessageRoot (`0x10005`) slot `0x04` (aggregation-tree
//!   height) then `nodes[height][0]`. Read at POST-batch state
//!   (`tree_root_after`); nonzero only when this chain is a settlement layer.
//!
//! The guest's `ProvenDB` only serves slots the server proved during ordinary
//! execution, so the server supplies these three slot proofs explicitly
//! (`types::InteropSlotProofs`). This module reproduces the native reads against
//! them and hands the results back to the commitment path, which uses the
//! derived values in place of the untrusted `BatchMeta` scalars. A proof whose
//! value or path is inconsistent with the pinned root fails verification here,
//! so a forged scalar cannot survive.
//!
//! Slot-derivation reference: `read_multichain_root` /
//! `calculate_multichain_root_slot` (native) and the server mirror
//! `lib/storage_api/src/read_multichain_root.rs`.

use revm::primitives::{B256, U256};

use crate::hash::keccak256;
use crate::merkle::{self, StorageProof};
use crate::types::InteropSlotProofs;

/// SystemContext, address `0x800b`.
const SYSTEM_CONTEXT_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x0b,
];

/// MessageRoot (L2 message-root aggregator), address `0x10005`.
const MESSAGE_ROOT_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x05,
];

/// Verify one interop slot proof recovers `expected_root` for `flat_key`, and
/// return the proven value (`None` = proven non-existent). Panics — like every
/// other proof check in the guest — on a malformed proof or a root mismatch,
/// which is exactly how a forged value/path is rejected.
fn verify_slot(
    proof: &StorageProof,
    flat_key: &B256,
    expected_root: &B256,
    what: &str,
) -> Option<B256> {
    let (root, value) = proof
        .verify(flat_key)
        .unwrap_or_else(|e| panic!("interop {what} proof failed for {flat_key}: {e}"));
    assert_eq!(
        root, *expected_root,
        "interop {what} proof recovers root {root}, expected {expected_root}"
    );
    value
}

/// Reproduce native `read_settlement_layer_chain_id`: SystemContext `0x800b`
/// slot 0, authenticated against the POST-batch tree root. `NonExisting` ⇒ 0.
/// Post-state is used for every batch: an upgrade batch may write the slot this
/// batch, and the post-state read observes that write instead of a stale value.
pub(super) fn derive_sl_chain_id(proof: &StorageProof, tree_root_after: &B256) -> u64 {
    let flat_key = merkle::derive_flat_storage_key(&SYSTEM_CONTEXT_ADDRESS, &B256::ZERO);
    let value = verify_slot(proof, &flat_key, tree_root_after, "sl_chain_id").unwrap_or(B256::ZERO);
    // The settlement-layer chain id is a small integer stored right-aligned in
    // the 32-byte word; the batch-output layout carries it as a u64.
    let bytes = value.0;
    assert!(
        bytes[..24].iter().all(|&b| b == 0),
        "settlement-layer chain id exceeds u64 ({value})"
    );
    u64::from_be_bytes(bytes[24..32].try_into().unwrap())
}

/// Reproduce native `read_multichain_root`: read the aggregation-tree height
/// (MessageRoot `0x10005` slot `0x04`), derive `nodes[height][0]`, and read it —
/// both authenticated against the POST-batch tree root. A chain that is not a
/// settlement layer has these slots absent (`NonExisting`) ⇒ 0.
pub(super) fn derive_multichain_root(proofs: &InteropSlotProofs, tree_root_after: &B256) -> B256 {
    const AGG_TREE_HEIGHT_SLOT: B256 = B256::with_last_byte(0x04);

    let height_key = merkle::derive_flat_storage_key(&MESSAGE_ROOT_ADDRESS, &AGG_TREE_HEIGHT_SLOT);
    let height = verify_slot(
        &proofs.multichain_height,
        &height_key,
        tree_root_after,
        "multichain height",
    )
    .unwrap_or(B256::ZERO);

    let root_slot = calculate_multichain_root_slot(&height);
    let root_key = merkle::derive_flat_storage_key(&MESSAGE_ROOT_ADDRESS, &root_slot);
    verify_slot(
        &proofs.multichain_root,
        &root_key,
        tree_root_after,
        "multichain root",
    )
    .unwrap_or(B256::ZERO)
}

/// Storage slot of `nodes[height][0]` in MessageRoot (`0x10005`).
///
/// The `_nodes` dynamic array lives at contract slot 6; solidity addresses
/// `_nodes[height][0]` as `keccak256( keccak256(6) + height )` (the inner index
/// 0 adds nothing). This mirrors native `calculate_multichain_root_slot` and the
/// server's `n_dim_array_key_in_layout(0x06, [height, 0])`.
fn calculate_multichain_root_slot(height: &B256) -> B256 {
    const AGG_TREE_NODES_SLOT: B256 = B256::with_last_byte(0x06);
    let base = U256::from_be_bytes(keccak256(AGG_TREE_NODES_SLOT.as_slice()).0);
    let nodes_height_array_slot = base.wrapping_add(U256::from_be_bytes(height.0));
    keccak256(&nodes_height_array_slot.to_be_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        empty_subtree_hash, hash_leaf, NeighborProofEntry, SlotProofEntry, TreeLeaf, TREE_DEPTH,
    };

    /// The slot-derivation must match the vectors pinned by native and the
    /// server (`read_multichain_root::test_calculate_multichain_root_slot_*`).
    #[test]
    fn multichain_root_slot_matches_reference_vectors() {
        let vec_for = |h: u8| calculate_multichain_root_slot(&B256::with_last_byte(h));
        assert_eq!(
            vec_for(1),
            "0x768c3a22b1e4688c94525eb9bc2cf1ce7601fc9e871dc6e10fc44f0f06340ce1"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            vec_for(3),
            "0x38ace9b5569ba016113e31884532182bc747997e743c0b7f9c307302b5f83760"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(
            vec_for(4),
            "0x35817d789b7a6dbe8b95b0f21e189fb26d3d329de699cac7a267a9568298e0a5"
                .parse::<B256>()
                .unwrap()
        );
    }

    // ---- tiny dense-tree builder over sorted (key, value) leaves -------------
    // Produces a root plus Existing/NonExisting proofs that verify against it.

    fn compress(l: &B256, r: &B256) -> B256 {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(l.as_slice());
        b[32..].copy_from_slice(r.as_slice());
        merkle::blake2s(&b)
    }

    /// Build a dense tree over MIN/MAX guards (idx 0, 1) + `data` leaves. Returns
    /// (root, leaves-by-index, per-leaf 64-long sibling paths).
    fn build_tree(data: &[(B256, B256)]) -> (B256, Vec<(u64, TreeLeaf)>, Vec<Vec<B256>>) {
        let mut recs: Vec<(u64, B256, B256)> =
            vec![(0, B256::ZERO, B256::ZERO), (1, B256::repeat_byte(0xff), B256::ZERO)];
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
            .map(|((idx, k, v), n)| (*idx, TreeLeaf { key: *k, value: *v, next_index: *n }))
            .collect();

        let mut levels: Vec<Vec<B256>> = vec![leaves
            .iter()
            .map(|(_, l)| hash_leaf(&l.key, &l.value, l.next_index))
            .collect()];
        while levels.last().unwrap().len() > 1 {
            let d = levels.len() - 1;
            let cur = levels.last().unwrap();
            let nl: Vec<B256> = (0..cur.len().div_ceil(2))
                .map(|i| {
                    let l = cur[2 * i];
                    let r = cur.get(2 * i + 1).copied().unwrap_or(empty_subtree_hash(d as u8));
                    compress(&l, &r)
                })
                .collect();
            levels.push(nl);
        }
        let mut root = levels.last().unwrap()[0];
        for d in (levels.len() - 1)..(TREE_DEPTH as usize) {
            root = compress(&root, &empty_subtree_hash(d as u8));
        }
        let siblings: Vec<Vec<B256>> = (0..leaves.len() as u64)
            .map(|i| {
                (0..TREE_DEPTH as usize)
                    .map(|d| {
                        let pos = ((i >> d) ^ 1) as usize;
                        levels
                            .get(d)
                            .and_then(|lvl| lvl.get(pos).copied())
                            .unwrap_or(empty_subtree_hash(d as u8))
                    })
                    .collect()
            })
            .collect();
        (root, leaves, siblings)
    }

    fn existing(leaves: &[(u64, TreeLeaf)], siblings: &[Vec<B256>], key: &B256) -> StorageProof {
        let (i, leaf) = leaves.iter().find(|(_, l)| l.key == *key).expect("leaf present");
        StorageProof::Existing(SlotProofEntry {
            index: *i,
            value: leaf.value,
            next_index: leaf.next_index,
            siblings: siblings[*i as usize].clone(),
        })
    }

    fn non_existing(leaves: &[(u64, TreeLeaf)], siblings: &[Vec<B256>], key: &B256) -> StorageProof {
        let (li, lleaf) = leaves
            .iter()
            .filter(|(_, l)| l.key < *key)
            .max_by_key(|(_, l)| l.key)
            .expect("MIN guard brackets below");
        let (ri, rleaf) = leaves.iter().find(|(i, _)| *i == lleaf.next_index).unwrap();
        let entry = |i: u64, l: &TreeLeaf| SlotProofEntry {
            index: i,
            value: l.value,
            next_index: l.next_index,
            siblings: siblings[i as usize].clone(),
        };
        StorageProof::NonExisting {
            left_neighbor: NeighborProofEntry { entry: entry(*li, lleaf), leaf_key: lleaf.key },
            right_neighbor: NeighborProofEntry { entry: entry(*ri, rleaf), leaf_key: rleaf.key },
        }
    }

    fn sl_key() -> B256 {
        merkle::derive_flat_storage_key(&SYSTEM_CONTEXT_ADDRESS, &B256::ZERO)
    }
    fn height_key() -> B256 {
        merkle::derive_flat_storage_key(&MESSAGE_ROOT_ADDRESS, &B256::with_last_byte(0x04))
    }
    fn root_key_for(height: &B256) -> B256 {
        merkle::derive_flat_storage_key(&MESSAGE_ROOT_ADDRESS, &calculate_multichain_root_slot(height))
    }

    /// `sl_chain_id` reads the value stored at `0x800b` slot 0.
    #[test]
    fn sl_chain_id_reads_stored_value() {
        let key = sl_key();
        let val = B256::from(U256::from(270u64));
        let (root, leaves, sib) = build_tree(&[(key, val)]);
        assert_eq!(derive_sl_chain_id(&existing(&leaves, &sib, &key), &root), 270);
    }

    /// A forged `sl_chain_id` (proof value/path not consistent with the pinned
    /// pre-state root) is rejected.
    #[test]
    fn sl_chain_id_forgery_rejected() {
        let key = sl_key();
        let (root, leaves, sib) = build_tree(&[(key, B256::from(U256::from(270u64)))]);
        // Tamper the proven value: recovers a different root than pinned.
        let mut forged = existing(&leaves, &sib, &key);
        if let StorageProof::Existing(e) = &mut forged {
            e.value = B256::from(U256::from(999u64));
        }
        assert!(std::panic::catch_unwind(|| derive_sl_chain_id(&forged, &root)).is_err());
    }

    /// Non-settlement-layer chain: both `0x10005` slots absent ⇒ multichain
    /// root 0.
    #[test]
    fn multichain_root_zero_when_not_settlement_layer() {
        // A tree with unrelated leaves; the 0x10005 slots do not exist.
        let filler = B256::repeat_byte(0x11);
        let (root, leaves, sib) = build_tree(&[(filler, B256::repeat_byte(0x22))]);
        let proofs = InteropSlotProofs {
            sl_chain_id: non_existing(&leaves, &sib, &sl_key()),
            multichain_height: non_existing(&leaves, &sib, &height_key()),
            multichain_root: non_existing(&leaves, &sib, &root_key_for(&B256::ZERO)),
        };
        assert_eq!(derive_multichain_root(&proofs, &root), B256::ZERO);
    }

    /// Settlement-layer chain: `0x10005` slot 0x04 holds a height, and
    /// `nodes[height][0]` holds the aggregation root ⇒ that root is returned.
    #[test]
    fn multichain_root_settlement_layer_returns_stored_root() {
        let height = B256::with_last_byte(4);
        let agg_root = B256::repeat_byte(0xab);
        let hkey = height_key();
        let rkey = root_key_for(&height);
        let (root, leaves, sib) = build_tree(&[(hkey, height), (rkey, agg_root)]);
        let proofs = InteropSlotProofs {
            sl_chain_id: non_existing(&leaves, &sib, &sl_key()),
            multichain_height: existing(&leaves, &sib, &hkey),
            multichain_root: existing(&leaves, &sib, &rkey),
        };
        assert_eq!(derive_multichain_root(&proofs, &root), agg_root);
    }

    /// A forged multichain root (root-slot proof value inconsistent with the
    /// pinned post-state root) is rejected.
    #[test]
    fn multichain_root_forgery_rejected() {
        let height = B256::with_last_byte(4);
        let hkey = height_key();
        let rkey = root_key_for(&height);
        let (root, leaves, sib) = build_tree(&[(hkey, height), (rkey, B256::repeat_byte(0xab))]);
        let mut forged_root = existing(&leaves, &sib, &rkey);
        if let StorageProof::Existing(e) = &mut forged_root {
            e.value = B256::repeat_byte(0xff); // claim a different aggregation root
        }
        let proofs = InteropSlotProofs {
            sl_chain_id: non_existing(&leaves, &sib, &sl_key()),
            multichain_height: existing(&leaves, &sib, &hkey),
            multichain_root: forged_root,
        };
        assert!(std::panic::catch_unwind(|| derive_multichain_root(&proofs, &root)).is_err());
    }
}
