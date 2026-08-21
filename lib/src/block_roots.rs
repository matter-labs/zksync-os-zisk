//! The per-block `transactions_root` and `receipts_root` that the AtlasV4
//! block header carries.
//!
//! Both are fixed-height binary Blake2s Merkle trees of depth 32 over the
//! block's leaves, padded to capacity with the zero empty leaf (zksync-os
//! `basic_bootloader .../block_flow/zk/block_data.rs` and
//! `zk_ee/src/common_structs/merkle_tree.rs`). A node hash is
//! `blake2s(left32 ‖ right32)`: no domain tag, no length prefix.
//!
//! A transaction leaf is the transaction hash itself, unhashed. A receipt leaf
//! is `blake2s(type_byte? ‖ rlp([status, cumulative_gas_used, bloom, [logs]]))`
//! with an all-zero bloom. The bloom is zero by design: the ZK block header
//! commits a zero logs bloom, so a real per-receipt bloom would be prover work
//! with no consumer.

use alloy_consensus::{Eip658Value, Receipt, RlpEncodableReceipt};
use alloy_primitives::{Bloom, Log, B256};
use blake2::digest::FixedOutput;
use blake2::{Blake2s256, Digest};

/// Height of the per-block transaction and receipt trees.
pub const BLOCK_TX_TREE_DEPTH: usize = 32;

fn blake2s_compress(lhs: &B256, rhs: &B256) -> B256 {
    let mut h = Blake2s256::new();
    h.update(lhs.as_slice());
    h.update(rhs.as_slice());
    B256::from_slice(&h.finalize_fixed())
}

/// The empty-subtree hashes of a tree of the given height: entry `i` is the
/// root of an empty subtree of height `i`, so entry `0` is the zero empty leaf
/// and `entry[i] = blake2s(entry[i - 1] ‖ entry[i - 1])`.
fn empty_subtree_hashes(height: usize) -> Vec<B256> {
    let mut hashes = Vec::with_capacity(height + 1);
    hashes.push(B256::ZERO);
    for i in 1..=height {
        let prev = hashes[i - 1];
        hashes.push(blake2s_compress(&prev, &prev));
    }
    hashes
}

/// Root of a fixed-height binary Blake2s tree whose leaves are `leaves`, padded
/// up to `2^height` with the empty leaf. `empty_subtree_hashes[i]` is the root
/// of an empty subtree of height `i`, and its length sets the height.
///
/// A leaf count above the tree capacity is rejected rather than folded: the
/// fold stops after `height` levels, so it would silently return a subtree root
/// that is not the tree's root.
fn merkle_root(leaves: &[B256], empty_subtree_hashes: &[B256]) -> B256 {
    assert!(
        !empty_subtree_hashes.is_empty(),
        "empty_subtree_hashes must carry at least the empty-leaf hash"
    );
    let height = empty_subtree_hashes.len() - 1;
    assert!(
        height >= 64 || leaves.len() as u64 <= 1u64 << height,
        "leaf count {} exceeds the height-{height} tree capacity",
        leaves.len(),
    );

    if leaves.is_empty() {
        return empty_subtree_hashes[height];
    }

    let mut nodes = leaves.to_vec();
    let mut count = nodes.len();
    for level in 0..height {
        let pairs = count.div_ceil(2);
        for i in 0..pairs {
            let left = nodes[i * 2];
            let right = if i * 2 + 1 < count {
                nodes[i * 2 + 1]
            } else {
                empty_subtree_hashes[level]
            };
            nodes[i] = blake2s_compress(&left, &right);
        }
        count = pairs;
    }
    nodes[0]
}

/// Fold a block's transaction hashes or receipt leaves into the depth-32
/// Blake2s root the block header carries.
pub fn block_tx_tree_root(leaves: &[B256]) -> B256 {
    merkle_root(leaves, &empty_subtree_hashes(BLOCK_TX_TREE_DEPTH))
}

/// The receipt leaf of one transaction:
/// `blake2s(type_byte? ‖ rlp([status, cumulative_gas_used, zero_bloom, [logs]]))`.
///
/// `tx_type` is the transaction's own type byte, and it prefixes the RLP for
/// every type other than 0 (legacy). `cumulative_gas_used` is the block's
/// running gas total including this transaction. `logs` are the transaction's
/// EVM logs, in emission order, after every revert has been applied.
///
/// TRUSTED INPUT: `cumulative_gas_used` descends from `TxInput::gas_used_override`,
/// which is witness data bounded only by the transaction gas limit. Through this
/// leaf it reaches `receipts_root`, the header hash, the block-hash ring and
/// `state_after`. The guest cannot derive native's gas, because native charges
/// pubdata and native resources that REVM does not model.
pub fn receipt_leaf(tx_type: u8, success: bool, cumulative_gas_used: u64, logs: &[Log]) -> B256 {
    let receipt = Receipt {
        status: Eip658Value::Eip658(success),
        cumulative_gas_used,
        logs: logs.iter().collect::<Vec<&Log>>(),
    };
    let prefix_len = usize::from(tx_type != 0);
    let mut encoded =
        Vec::with_capacity(prefix_len + receipt.rlp_encoded_length_with_bloom(&Bloom::ZERO));
    if tx_type != 0 {
        encoded.push(tx_type);
    }
    receipt.rlp_encode_with_bloom(&Bloom::ZERO, &mut encoded);

    let mut h = Blake2s256::new();
    h.update(&encoded);
    B256::from_slice(&h.finalize_fixed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, LogData};

    /// The depth-32 empty-subtree table follows the Blake2s recurrence from the
    /// zero leaf, and its top entry is the value native hardcodes for the
    /// all-empty per-block tree.
    #[test]
    fn empty_subtree_table_follows_the_recurrence_and_pins_native_root() {
        let table = empty_subtree_hashes(BLOCK_TX_TREE_DEPTH);
        assert_eq!(table.len(), BLOCK_TX_TREE_DEPTH + 1);
        assert_eq!(table[0], B256::ZERO, "the empty leaf is the zero hash");
        for level in 1..table.len() {
            let prev = table[level - 1];
            assert_eq!(table[level], blake2s_compress(&prev, &prev), "level {level}");
        }
        let native_empty_root: B256 =
            "0x41cd2b2f5025ff1c3989656b0a7826b9af5796b440e26ebffe5cd14fc69ab100"
                .parse()
                .unwrap();
        assert_eq!(table[BLOCK_TX_TREE_DEPTH], native_empty_root);
    }

    /// A block with no transactions commits the all-empty tree root for both
    /// header fields.
    #[test]
    fn empty_leaf_list_returns_the_empty_tree_root() {
        let native_empty_root: B256 =
            "0x41cd2b2f5025ff1c3989656b0a7826b9af5796b440e26ebffe5cd14fc69ab100"
                .parse()
                .unwrap();
        assert_eq!(block_tx_tree_root(&[]), native_empty_root);
    }

    /// Naive reference: pad the leaf list to `2^height` with the empty leaf and
    /// fold every level in full. The production fold skips the all-empty right
    /// side of each level, so the two must agree for every leaf count.
    fn padded_reference_root(leaves: &[B256], height: usize) -> B256 {
        let mut level: Vec<B256> = leaves.to_vec();
        level.resize(1usize << height, B256::ZERO);
        for _ in 0..height {
            level = level
                .chunks(2)
                .map(|pair| blake2s_compress(&pair[0], &pair[1]))
                .collect();
        }
        level[0]
    }

    /// The fold equals the fully padded reference tree for every leaf count a
    /// height-6 tree admits, including zero and a full tree.
    #[test]
    fn fold_matches_the_padded_reference_tree() {
        const HEIGHT: usize = 6;
        let table = empty_subtree_hashes(HEIGHT);
        for count in 0..=(1usize << HEIGHT) {
            let leaves: Vec<B256> = (0..count).map(|i| B256::repeat_byte(i as u8 + 1)).collect();
            assert_eq!(
                merkle_root(&leaves, &table),
                padded_reference_root(&leaves, HEIGHT),
                "leaf count {count}",
            );
        }
    }

    /// More leaves than the tree holds is rejected. The fold would otherwise
    /// return a subtree root that is not the tree's root.
    #[test]
    #[should_panic(expected = "exceeds the height-3 tree capacity")]
    fn leaf_count_above_capacity_is_rejected() {
        let table = empty_subtree_hashes(3);
        let leaves: Vec<B256> = (0..9u8).map(B256::repeat_byte).collect();
        merkle_root(&leaves, &table);
    }

    /// Native's receipt vector (`block_flow/zk/receipt.rs`): type 2, status
    /// true, cumulative gas `0x5208`, one log with address `0xaa..aa`, topics
    /// `0x11..11` and `0x22..22`, and data `0xdeadbeef`.
    fn native_receipt_vector_log() -> Log {
        Log {
            address: Address::from([0xaa; 20]),
            data: LogData::new_unchecked(
                vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
                Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            ),
        }
    }

    /// Hand-built `rlp([status, cumulative_gas_used, bloom, [log]])` for the
    /// native vector, with the caller's bloom. Written out byte by byte so the
    /// encoding is derived from the RLP rules rather than from the encoder the
    /// production path uses.
    fn native_receipt_vector_rlp(bloom_byte: u8) -> Vec<u8> {
        let mut log = Vec::new();
        log.push(0x94); // 20-byte string: the address
        log.extend_from_slice(&[0xaa; 20]);
        log.extend_from_slice(&[0xf8, 0x42]); // list, payload 66: two topics
        log.push(0xa0);
        log.extend_from_slice(&[0x11; 32]);
        log.push(0xa0);
        log.extend_from_slice(&[0x22; 32]);
        log.push(0x84); // 4-byte string: the data
        log.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let mut encoded_log = Vec::new();
        encoded_log.extend_from_slice(&[0xf8, log.len() as u8]); // the log itself
        encoded_log.extend_from_slice(&log);

        let mut logs = Vec::new();
        logs.extend_from_slice(&[0xf8, encoded_log.len() as u8]); // list of one log
        logs.extend_from_slice(&encoded_log);

        let mut fields = Vec::new();
        fields.push(0x01); // status: true
        fields.extend_from_slice(&[0x82, 0x52, 0x08]); // cumulative gas 0x5208
        fields.extend_from_slice(&[0xb9, 0x01, 0x00]); // 256-byte string: the bloom
        fields.extend_from_slice(&[bloom_byte; 256]);
        fields.extend_from_slice(&logs);

        let mut out = Vec::new();
        out.push(0xf9); // list with a two-byte length
        out.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        out.extend_from_slice(&fields);
        out
    }

    fn blake2s(bytes: &[u8]) -> B256 {
        let mut h = Blake2s256::new();
        h.update(bytes);
        B256::from_slice(&h.finalize_fixed())
    }

    /// The receipt leaf reproduces native's vector, and it commits the zero
    /// bloom rather than the bloom those logs would really produce.
    #[test]
    fn receipt_leaf_matches_the_native_vector_and_uses_a_zero_bloom() {
        let logs = [native_receipt_vector_log()];
        let leaf = receipt_leaf(2, true, 0x5208, &logs);

        let mut expected = vec![2u8]; // the type byte prefixes a typed receipt
        expected.extend_from_slice(&native_receipt_vector_rlp(0x00));
        assert_eq!(leaf, blake2s(&expected));

        let mut with_full_bloom = vec![2u8];
        with_full_bloom.extend_from_slice(&native_receipt_vector_rlp(0xff));
        assert_ne!(leaf, blake2s(&with_full_bloom));
    }

    /// A legacy transaction writes no type-byte prefix; every other type does.
    #[test]
    fn only_a_typed_transaction_prefixes_its_type_byte() {
        let logs = [native_receipt_vector_log()];
        let body = native_receipt_vector_rlp(0x00);

        assert_eq!(receipt_leaf(0, true, 0x5208, &logs), blake2s(&body));

        for tx_type in [1u8, 2, 4, 0x7d, 0x7e, 0x7f] {
            let mut prefixed = vec![tx_type];
            prefixed.extend_from_slice(&body);
            assert_eq!(
                receipt_leaf(tx_type, true, 0x5208, &logs),
                blake2s(&prefixed),
                "type {tx_type:#04x}",
            );
        }
    }

    /// The status flag, the cumulative gas and the log set each change the leaf,
    /// so none of them is dropped on the way into the tree.
    #[test]
    fn every_receipt_field_reaches_the_leaf() {
        let logs = [native_receipt_vector_log()];
        let base = receipt_leaf(2, true, 0x5208, &logs);
        assert_ne!(base, receipt_leaf(2, false, 0x5208, &logs));
        assert_ne!(base, receipt_leaf(2, true, 0x5209, &logs));
        assert_ne!(base, receipt_leaf(2, true, 0x5208, &[]));
    }
}

