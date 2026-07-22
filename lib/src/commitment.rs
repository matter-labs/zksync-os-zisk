//! Batch commitment computation: Keccak-based hashing for state commitments,
//! batch output hashes, L2→L1 log merkle trees, DA commitments, and priority ops.

use alloy_primitives::B256;
use blake2::digest::FixedOutput;
use blake2::{Blake2s256, Digest};

// Re-export the accelerated keccak256.
pub(crate) use crate::hash::keccak256;

fn keccak_compress(lhs: &B256, rhs: &B256) -> B256 {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(lhs.as_slice());
    data[32..64].copy_from_slice(rhs.as_slice());
    keccak256(&data)
}

/// Keccak256 of two concatenated B256 values.
pub fn keccak_two(a: &B256, b: &B256) -> B256 {
    keccak_compress(a, b)
}

// ---------------------------------------------------------------------------
// State commitment (Blake2s)
// ---------------------------------------------------------------------------

/// Compute the state commitment hash:
/// Blake2s256(tree_root || leaf_count_be8 || block_number_be8 || block_hashes_blake || timestamp_be8)
pub fn state_commitment_hash(
    tree_root: &B256,
    leaf_count: u64,
    block_number: u64,
    block_hashes_blake: &B256,
    last_block_timestamp: u64,
) -> B256 {
    let mut h = Blake2s256::new();
    h.update(tree_root.as_slice());
    h.update(leaf_count.to_be_bytes());
    h.update(block_number.to_be_bytes());
    h.update(block_hashes_blake.as_slice());
    h.update(last_block_timestamp.to_be_bytes());
    B256::from_slice(&h.finalize_fixed())
}

/// Compute the last_256_block_hashes_blake:
/// Blake2s256(block_hash[1] || block_hash[2] || ... || block_hash[255] || current_block_hash)
/// where block_hash[i] are the previous 255 block hashes (index 1..=255 of the 256-entry array).
pub fn block_hashes_blake(previous_255_hashes: &[B256], current_block_hash: &B256) -> B256 {
    // Match Airbender: block_hashes.0.iter().skip(1) then current.
    // Order: [block_hashes[1], ..., block_hashes[255], current_block_hash]
    let mut h = Blake2s256::new();
    for hash in previous_255_hashes {
        h.update(hash.as_slice());
    }
    h.update(current_block_hash.as_slice());
    B256::from_slice(&h.finalize_fixed())
}

// ---------------------------------------------------------------------------
// L2→L1 logs Keccak merkle tree (height 14)
// ---------------------------------------------------------------------------

pub const L2_TO_L1_LOG_SIZE: usize = 88;
const L2_TO_L1_TREE_HEIGHT: usize = 14;

/// Compute the L2→L1 logs merkle root (Keccak binary tree, height 14).
/// Each leaf is keccak256 of an 88-byte encoded L2ToL1Log.
/// Empty leaves are keccak256([0u8; 88]).
pub fn l2_to_l1_logs_root(encoded_logs: &[[u8; L2_TO_L1_LOG_SIZE]]) -> B256 {
    // The fixed-height fold silently returns a subtree root (not the true root)
    // once the leaves exceed the tree capacity, so reject that case rather than
    // commit a wrong root that only cross-prover disagreement would catch.
    assert!(
        encoded_logs.len() <= 1 << L2_TO_L1_TREE_HEIGHT,
        "L2->L1 log count {} exceeds the height-{L2_TO_L1_TREE_HEIGHT} tree capacity {}",
        encoded_logs.len(),
        1usize << L2_TO_L1_TREE_HEIGHT,
    );
    let empty_leaf = keccak256(&[0u8; L2_TO_L1_LOG_SIZE]);
    let mut empty_hashes = vec![empty_leaf];
    for _ in 0..L2_TO_L1_TREE_HEIGHT {
        let prev = *empty_hashes.last().unwrap();
        empty_hashes.push(keccak_compress(&prev, &prev));
    }

    if encoded_logs.is_empty() {
        return empty_hashes[L2_TO_L1_TREE_HEIGHT];
    }

    let mut hashes: Vec<B256> = encoded_logs.iter().map(|log| keccak256(log)).collect();
    let mut non_default_count = hashes.len();

    for level in 0..L2_TO_L1_TREE_HEIGHT {
        let pairs = (non_default_count + 1) / 2;
        for i in 0..pairs {
            let left = hashes[i * 2];
            let right = if i * 2 + 1 < non_default_count {
                hashes[i * 2 + 1]
            } else {
                empty_hashes[level]
            };
            hashes[i] = keccak_compress(&left, &right);
        }
        non_default_count = pairs;
    }

    if non_default_count > 0 {
        hashes[0]
    } else {
        empty_hashes[L2_TO_L1_TREE_HEIGHT]
    }
}

/// Released-line batch output hash layouts, mirroring the native
/// `PendingBatchInfo::public_input_hash` (zksync-os-server `batch_info.rs`,
/// abi-packed):
/// - **v30** (AtlasV1/V2): `(chain_id, first_ts, last_ts, da_scheme,
///   da_commitment, n_l1_txs, priority_ops_hash, l2_to_l1_logs_root,
///   upgrade_tx_hash, dependency_roots_rolling_hash)` — no layer-2 tx count,
///   no settlement-layer chain id.
/// - **v31** (AtlasV3): inserts `n_l2_txs` after `n_l1_txs` and appends
///   `sl_chain_id`.
/// The draft-0.4.0 chain_id-less layout returns at the AtlasV4 bump.
#[allow(clippy::too_many_arguments)]
pub fn batch_output_hash_native(
    v31_layout: bool,
    chain_id: u64,
    first_block_timestamp: u64,
    last_block_timestamp: u64,
    da_commitment_scheme: u8,
    da_commitment: &B256,
    number_of_layer1_txs: u64,
    number_of_layer2_txs: u64,
    priority_operations_hash: &B256,
    l2_to_l1_logs_root_hash: &B256,
    upgrade_tx_hash: &B256,
    interop_roots_rolling_hash: &B256,
    settlement_layer_chain_id: u64,
) -> B256 {
    let mut data = Vec::with_capacity(336);
    // chain_id as U256 BE
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&chain_id.to_be_bytes());
    data.extend_from_slice(&first_block_timestamp.to_be_bytes());
    data.extend_from_slice(&last_block_timestamp.to_be_bytes());
    data.extend_from_slice(&[0u8; 31]);
    data.push(da_commitment_scheme);
    data.extend_from_slice(da_commitment.as_slice());
    // number_of_layer_1_txs as U256 BE (24 zero bytes + u64 BE)
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&number_of_layer1_txs.to_be_bytes());
    if v31_layout {
        // number_of_layer_2_txs as U256 BE
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&number_of_layer2_txs.to_be_bytes());
    }
    data.extend_from_slice(priority_operations_hash.as_slice());
    data.extend_from_slice(l2_to_l1_logs_root_hash.as_slice());
    data.extend_from_slice(upgrade_tx_hash.as_slice());
    data.extend_from_slice(interop_roots_rolling_hash.as_slice());
    if v31_layout {
        // settlement_layer_chain_id as U256 BE
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&settlement_layer_chain_id.to_be_bytes());
    }
    keccak256(&data)
}

/// Canonical keccak256 commitment to the chain config, matching zksync-os
/// draft-0.4.0 `ChainConfig::hash` (zk_ee .../metadata/chain_config.rs):
///   chain_id (uint256 BE), fri_proof_verification_enabled (32-byte word,
///   last byte 0/1), max_tx_gas_limit (u64 BE, right-aligned in a 32-byte word).
pub fn chain_config_hash(
    chain_id: u64,
    fri_proof_verification_enabled: bool,
    max_tx_gas_limit: u64,
) -> B256 {
    let mut data = [0u8; 96];
    // chain_id as U256 BE
    data[24..32].copy_from_slice(&chain_id.to_be_bytes());
    // fri word: last byte 0/1
    data[63] = u8::from(fri_proof_verification_enabled);
    // max_tx_gas_limit right-aligned in the third 32-byte word
    data[88..96].copy_from_slice(&max_tx_gas_limit.to_be_bytes());
    keccak256(&data)
}

/// Priority operations rolling hash.
/// Initial: keccak256([]) = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
/// For each L1 tx: hash = keccak256(prev_hash || tx_hash)
pub fn priority_ops_rolling_hash(l1_tx_hashes: &[B256]) -> B256 {
    let mut hash = keccak256(&[]);
    for tx_hash in l1_tx_hashes {
        hash = keccak_compress(&hash, tx_hash);
    }
    hash
}

/// DA commitment for calldata mode:
/// keccak256(0x00*32 || keccak256(pubdata) || 0x01 || 0x00*32)
pub fn da_commitment_calldata(pubdata: &[u8]) -> B256 {
    let mut data = Vec::with_capacity(97);
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(keccak256(pubdata).as_slice());
    data.push(1u8);
    data.extend_from_slice(&[0u8; 32]);
    keccak256(&data)
}

/// DA commitment for blob mode (BlobsZKsyncOS, scheme=4):
/// keccak256(versioned_hash_0 || versioned_hash_1 || ...)
pub fn da_commitment_blobs(versioned_hashes: &[B256]) -> B256 {
    let mut data = Vec::with_capacity(versioned_hashes.len() * 32);
    for hash in versioned_hashes {
        data.extend_from_slice(hash.as_slice());
    }
    keccak256(&data)
}

/// Full batch public input hash, matching zksync-os draft-0.4.0
/// `BatchPublicInput::hash` (basic_bootloader .../zk/post_tx_op/public_input.rs):
/// Keccak256(state_before || state_after || chain_config_hash || batch_output_hash)
pub fn batch_public_input_hash(
    state_before: &B256,
    state_after: &B256,
    chain_config_hash: &B256,
    batch_output_hash: &B256,
) -> B256 {
    let mut data = [0u8; 128];
    data[..32].copy_from_slice(state_before.as_slice());
    data[32..64].copy_from_slice(state_after.as_slice());
    data[64..96].copy_from_slice(chain_config_hash.as_slice());
    data[96..128].copy_from_slice(batch_output_hash.as_slice());
    keccak256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ops_hash_empty() {
        let expected: B256 =
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                .parse()
                .unwrap();
        assert_eq!(priority_ops_rolling_hash(&[]), expected);
    }

    #[test]
    fn l2_logs_root_empty() {
        let root = l2_to_l1_logs_root(&[]);
        let empty_leaf = keccak256(&[0u8; L2_TO_L1_LOG_SIZE]);
        let mut h = empty_leaf;
        for _ in 0..L2_TO_L1_TREE_HEIGHT {
            h = keccak_compress(&h, &h);
        }
        assert_eq!(root, h);
    }
}
