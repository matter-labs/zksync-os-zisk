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

/// Root of a fixed-height binary keccak merkle tree whose leaves are `leaves`,
/// padded up to `2^height` with the empty leaf. `empty_subtree_hashes[i]` is
/// the root of an empty subtree of height `i` (index 0 is the empty leaf), and
/// its length sets `height = len - 1`.
///
/// Mirrors native `merkle_root_in_place`
/// (`zk_ee/src/common_structs/merkle_tree.rs`): the node hash is
/// `keccak256(left ‖ right)` with no domain tag, and a missing right sibling at
/// fold level `level` takes `empty_subtree_hashes[level]`.
fn fixed_height_keccak_root(leaves: &[B256], empty_subtree_hashes: &[B256]) -> B256 {
    let height = empty_subtree_hashes.len() - 1;
    // The fold silently returns a subtree root (not the true root) once the
    // leaves exceed the tree capacity, so reject that case rather than commit a
    // wrong root that only cross-prover disagreement would catch.
    assert!(
        leaves.len() <= 1usize << height,
        "leaf count {} exceeds the height-{height} tree capacity {}",
        leaves.len(),
        1usize << height,
    );
    if leaves.is_empty() {
        return empty_subtree_hashes[height];
    }

    let mut nodes = leaves.to_vec();
    let mut count = nodes.len();
    for level in 0..height {
        let pairs = (count + 1) / 2;
        for i in 0..pairs {
            let left = nodes[i * 2];
            let right = if i * 2 + 1 < count {
                nodes[i * 2 + 1]
            } else {
                empty_subtree_hashes[level]
            };
            nodes[i] = keccak_compress(&left, &right);
        }
        count = pairs;
    }
    nodes[0]
}

/// The empty-subtree hashes of a keccak tree of `height` over `empty_leaf`,
/// under the recurrence `entry[i] = keccak256(entry[i-1] ‖ entry[i-1])`.
fn empty_subtree_hashes(empty_leaf: B256, height: usize) -> Vec<B256> {
    let mut hashes = Vec::with_capacity(height + 1);
    hashes.push(empty_leaf);
    for level in 1..=height {
        let prev = hashes[level - 1];
        hashes.push(keccak_compress(&prev, &prev));
    }
    hashes
}

/// Compute the L2→L1 logs merkle root (Keccak binary tree, height 14).
/// Each leaf is keccak256 of an 88-byte encoded L2ToL1Log.
/// Empty leaves are keccak256([0u8; 88]).
pub fn l2_to_l1_logs_root(encoded_logs: &[[u8; L2_TO_L1_LOG_SIZE]]) -> B256 {
    let empty_hashes = empty_subtree_hashes(keccak256(&[0u8; L2_TO_L1_LOG_SIZE]), L2_TO_L1_TREE_HEIGHT);
    let leaves: Vec<B256> = encoded_logs.iter().map(|log| keccak256(log)).collect();
    fixed_height_keccak_root(&leaves, &empty_hashes)
}

/// Height of the chain batch root tree: capacity `2^3 == 8` leaves, of which
/// four are live and four are reserved.
const CHAIN_BATCH_ROOT_TREE_HEIGHT: usize = 3;

/// Empty-subtree hashes of the chain batch root tree, where entry `i` is the
/// root of an empty subtree of height `i` over the all-zero reserved leaf.
/// `chain_batch_root_empty_hashes_match_the_recurrence` locks the table.
const CHAIN_BATCH_ROOT_EMPTY_SUBTREE_HASHES: [[u8; 32]; CHAIN_BATCH_ROOT_TREE_HEIGHT + 1] = [
    [0u8; 32],
    [
        0xad, 0x32, 0x28, 0xb6, 0x76, 0xf7, 0xd3, 0xcd, 0x42, 0x84, 0xa5, 0x44, 0x3f, 0x17, 0xf1,
        0x96, 0x2b, 0x36, 0xe4, 0x91, 0xb3, 0x0a, 0x40, 0xb2, 0x40, 0x58, 0x49, 0xe5, 0x97, 0xba,
        0x5f, 0xb5,
    ],
    [
        0xb4, 0xc1, 0x19, 0x51, 0x95, 0x7c, 0x6f, 0x8f, 0x64, 0x2c, 0x4a, 0xf6, 0x1c, 0xd6, 0xb2,
        0x46, 0x40, 0xfe, 0xc6, 0xdc, 0x7f, 0xc6, 0x07, 0xee, 0x82, 0x06, 0xa9, 0x9e, 0x92, 0x41,
        0x0d, 0x30,
    ],
    [
        0x21, 0xdd, 0xb9, 0xa3, 0x56, 0x81, 0x5c, 0x3f, 0xac, 0x10, 0x26, 0xb6, 0xde, 0xc5, 0xdf,
        0x31, 0x24, 0xaf, 0xba, 0xdb, 0x48, 0x5c, 0x9b, 0xa5, 0xa3, 0xe3, 0x39, 0x8a, 0x04, 0xb7,
        0xba, 0x85,
    ],
];

/// The chain batch root a spec commits as the `l2_logs_tree_root` field of its
/// batch output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainBatchRootLayout {
    /// AtlasV1 through AtlasV3: `keccak256(l2_logs_root ‖ multichain_root)`.
    TwoPreimageKeccak,
    /// AtlasV4: a fixed height-3, eight-leaf keccak merkle tree.
    HeightThreeMerkle,
}

/// The chain batch root, mirroring native `compute_chain_batch_root`
/// (`.../zk/post_tx_op/mod.rs`).
///
/// The AtlasV4 tree holds four live leaves — the L2→L1 logs root, the
/// multichain root, and the interop commitment tree root at the batch begin and
/// at the batch end — followed by four reserved zero leaves. The earlier specs
/// hash the first two leaves and nothing else, so the two forms never coincide:
/// even an all-zero input differs.
pub fn chain_batch_root(
    layout: ChainBatchRootLayout,
    l2_logs_root: &B256,
    multichain_root: &B256,
    commitment_tree_root_begin: &B256,
    commitment_tree_root_end: &B256,
) -> B256 {
    match layout {
        ChainBatchRootLayout::TwoPreimageKeccak => keccak_compress(l2_logs_root, multichain_root),
        ChainBatchRootLayout::HeightThreeMerkle => {
            let empty_hashes: Vec<B256> = CHAIN_BATCH_ROOT_EMPTY_SUBTREE_HASHES
                .iter()
                .map(|entry| B256::from(*entry))
                .collect();
            fixed_height_keccak_root(
                &[
                    *l2_logs_root,
                    *multichain_root,
                    *commitment_tree_root_begin,
                    *commitment_tree_root_end,
                ],
                &empty_hashes,
            )
        }
    }
}

/// The batch-output preimage layout a spec commits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BatchOutputLayout {
    /// AtlasV1 and AtlasV2 (protocol v30): `(chain_id, first_ts, last_ts,
    /// da_scheme, da_commitment, n_l1_txs, priority_ops_hash,
    /// l2_to_l1_logs_root, upgrade_tx_hash, interop_roots_rolling_hash)`.
    V30,
    /// AtlasV3 (protocol v31): inserts `n_l2_txs` after `n_l1_txs` and appends
    /// `sl_chain_id`.
    V31,
    /// AtlasV4: the AtlasV3 field list without the leading `chain_id` word. The
    /// chain identity moves up into `chain_config_hash` in the top-level batch
    /// public input.
    AtlasV4,
}

/// Batch output hash, mirroring the native `BatchOutput::hash`
/// (basic_bootloader `.../zk/post_tx_op/public_input.rs`, abi-packed) of the
/// spec that executed the batch. See [`BatchOutputLayout`] for the field lists.
#[allow(clippy::too_many_arguments)]
pub fn batch_output_hash_native(
    layout: BatchOutputLayout,
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
    let v31_tail = layout != BatchOutputLayout::V30;
    let mut data = Vec::with_capacity(336);
    if layout != BatchOutputLayout::AtlasV4 {
        // chain_id as U256 BE
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&chain_id.to_be_bytes());
    }
    data.extend_from_slice(&first_block_timestamp.to_be_bytes());
    data.extend_from_slice(&last_block_timestamp.to_be_bytes());
    data.extend_from_slice(&[0u8; 31]);
    data.push(da_commitment_scheme);
    data.extend_from_slice(da_commitment.as_slice());
    // number_of_layer_1_txs as U256 BE (24 zero bytes + u64 BE)
    data.extend_from_slice(&[0u8; 24]);
    data.extend_from_slice(&number_of_layer1_txs.to_be_bytes());
    if v31_tail {
        // number_of_layer_2_txs as U256 BE
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&number_of_layer2_txs.to_be_bytes());
    }
    data.extend_from_slice(priority_operations_hash.as_slice());
    data.extend_from_slice(l2_to_l1_logs_root_hash.as_slice());
    data.extend_from_slice(upgrade_tx_hash.as_slice());
    data.extend_from_slice(interop_roots_rolling_hash.as_slice());
    if v31_tail {
        // settlement_layer_chain_id as U256 BE
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&settlement_layer_chain_id.to_be_bytes());
    }
    keccak256(&data)
}

/// Canonical keccak256 commitment to the chain config, matching zksync-os
/// `ChainConfig::hash` (zk_ee .../metadata/chain_config.rs):
///   chain_id (uint256 BE), fri_proof_verification_enabled (32-byte word,
///   last byte 0/1), max_tx_gas_limit (u64 BE, right-aligned in a 32-byte
///   word), pubdata_content (32-byte word, last byte the mode id).
///
/// era-contracts `Executor._getBatchProofPublicInputZKsyncOS` holds the same
/// encoding, so L1 can gate the two proving lanes against each other.
pub fn chain_config_hash(
    chain_id: u64,
    fri_proof_verification_enabled: bool,
    max_tx_gas_limit: u64,
    pubdata_content: u8,
) -> B256 {
    let mut data = [0u8; 128];
    // chain_id as U256 BE
    data[24..32].copy_from_slice(&chain_id.to_be_bytes());
    // fri word: last byte 0/1
    data[63] = u8::from(fri_proof_verification_enabled);
    // max_tx_gas_limit right-aligned in the third 32-byte word
    data[88..96].copy_from_slice(&max_tx_gas_limit.to_be_bytes());
    // pubdata_content mode id in the last byte of the fourth 32-byte word
    data[127] = pubdata_content;
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

/// Full batch public input hash, matching the native `BatchPublicInput::hash`
/// (basic_bootloader .../zk/post_tx_op/public_input.rs) of the spec that
/// executed the batch.
///
/// - AtlasV1 through AtlasV3 (`chain_config_hash = None`): three words,
///   `keccak256(state_before ‖ state_after ‖ batch_output_hash)`.
/// - AtlasV4 (`chain_config_hash = Some(..)`): four words, with the chain-config
///   commitment as the third.
///
/// The caller passes the option so the layout choice stays a single explicit
/// decision at the spec gate.
pub fn batch_public_input_hash(
    state_before: &B256,
    state_after: &B256,
    chain_config_hash: Option<&B256>,
    batch_output_hash: &B256,
) -> B256 {
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(state_before.as_slice());
    data.extend_from_slice(state_after.as_slice());
    if let Some(chain_config_hash) = chain_config_hash {
        data.extend_from_slice(chain_config_hash.as_slice());
    }
    data.extend_from_slice(batch_output_hash.as_slice());
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

    /// Native's own golden vector for the AtlasV4 batch output
    /// (`.../zk/post_tx_op/public_input.rs`, `batch_output_hash_golden_vector`):
    /// first timestamp 1, last timestamp 2, DA scheme
    /// `BlobsAndPubdataKeccak256` (3), zero pubdata commitment, 3 layer-1 txs,
    /// 4 layer-2 txs, zero priority hash, zero logs root, zero upgrade hash,
    /// zero interop rolling hash and settlement-layer chain id 9. The chain id
    /// is absent from the preimage, so any value must give the same hash.
    #[test]
    fn atlas_v4_batch_output_matches_the_native_golden_vector() {
        let expected: B256 =
            "0x1c24f398aa0701f9348912ecca748ba93bfb84bfe4f283c16514311419f4f658"
                .parse()
                .unwrap();
        for chain_id in [0u64, 37, u64::MAX] {
            assert_eq!(
                batch_output_hash_native(
                    BatchOutputLayout::AtlasV4,
                    chain_id,
                    1,
                    2,
                    3,
                    &B256::ZERO,
                    3,
                    4,
                    &B256::ZERO,
                    &B256::ZERO,
                    &B256::ZERO,
                    &B256::ZERO,
                    9,
                ),
                expected,
            );
        }
    }

    /// Native's own golden vector for `ChainConfig::hash`
    /// (`.../zk/post_tx_op/public_input.rs`, `chain_config_hash_golden_vector`):
    /// chain id 37, FRI proof verification disabled, the EIP-7825 default
    /// per-transaction gas cap and full pubdata. era-contracts
    /// `Executor._getBatchProofPublicInputZKsyncOS` pins the same value, so a
    /// move here must move there too.
    #[test]
    fn chain_config_matches_the_native_golden_vector() {
        let expected: B256 =
            "0x9bba8b838beaad59a5dec253b49be1f496d47df8c2086b561298cae2cc232c0a"
                .parse()
                .unwrap();
        assert_eq!(chain_config_hash(37, false, 1 << 24, 0), expected);
    }

    /// Native's own golden vector for the whole batch public input
    /// (`.../zk/post_tx_op/public_input.rs`,
    /// `batch_public_input_hash_golden_vector`): zero state commitments, the
    /// chain config above, and the batch output of
    /// `atlas_v4_batch_output_matches_the_native_golden_vector`. era-contracts
    /// `ZKsyncOSPublicInput.t.sol::PUBLIC_INPUT_HASH_GOLDEN` pins the same value.
    #[test]
    fn batch_public_input_matches_the_native_golden_vector() {
        let batch_output = batch_output_hash_native(
            BatchOutputLayout::AtlasV4,
            37,
            1,
            2,
            3,
            &B256::ZERO,
            3,
            4,
            &B256::ZERO,
            &B256::ZERO,
            &B256::ZERO,
            &B256::ZERO,
            9,
        );
        let expected: B256 =
            "0x0a5143e28ed3fc1728ef4d96319f2306bb5a81bfccd908154e44029988ef9e7c"
                .parse()
                .unwrap();
        assert_eq!(
            batch_public_input_hash(
                &B256::ZERO,
                &B256::ZERO,
                Some(&chain_config_hash(37, false, 1 << 24, 0)),
                &batch_output,
            ),
            expected,
        );
    }

    /// Every chain-config word reaches the commitment, so a change in any one
    /// of the four moves the hash. Native pins the same property per field
    /// (`batch_public_input_hash_commits_to_*`).
    #[test]
    fn chain_config_commits_to_every_word() {
        let base = chain_config_hash(37, false, 1 << 24, 0);
        assert_ne!(base, chain_config_hash(38, false, 1 << 24, 0));
        assert_ne!(base, chain_config_hash(37, true, 1 << 24, 0));
        assert_ne!(base, chain_config_hash(37, false, 1 << 25, 0));
        assert_ne!(base, chain_config_hash(37, false, 1 << 24, 1));
    }

    /// The three layouts are distinct, and the v30 and v31 preimages keep the
    /// chain-id prefix. The lengths pin the field counts: v30 is 272 bytes, v31
    /// adds the layer-2 count and the settlement chain id, and AtlasV4 is v31
    /// without the chain-id word.
    #[test]
    fn batch_output_layouts_are_distinct() {
        let hash = |layout| {
            batch_output_hash_native(
                layout,
                37,
                1,
                2,
                3,
                &B256::ZERO,
                3,
                4,
                &B256::ZERO,
                &B256::ZERO,
                &B256::ZERO,
                &B256::ZERO,
                9,
            )
        };
        let v30 = hash(BatchOutputLayout::V30);
        let v31 = hash(BatchOutputLayout::V31);
        let v4 = hash(BatchOutputLayout::AtlasV4);
        assert_ne!(v30, v31);
        assert_ne!(v31, v4);
        assert_ne!(v30, v4);

        // The chain id reaches the v30 and v31 preimages and no other field
        // moves, so a different chain id must move both hashes.
        let other = |layout| {
            batch_output_hash_native(
                layout,
                38,
                1,
                2,
                3,
                &B256::ZERO,
                3,
                4,
                &B256::ZERO,
                &B256::ZERO,
                &B256::ZERO,
                &B256::ZERO,
                9,
            )
        };
        assert_ne!(v30, other(BatchOutputLayout::V30));
        assert_ne!(v31, other(BatchOutputLayout::V31));
    }

    /// The two public-input layouts are the plain concatenations native hashes,
    /// and they differ. AtlasV1 through AtlasV3 hash three words; AtlasV4 adds
    /// the chain-config commitment as the third of four.
    #[test]
    fn public_input_layouts_are_three_and_four_words() {
        let state_before = B256::repeat_byte(0x11);
        let state_after = B256::repeat_byte(0x22);
        let chain_config = B256::repeat_byte(0x33);
        let batch_output = B256::repeat_byte(0x44);

        let mut three = Vec::new();
        three.extend_from_slice(state_before.as_slice());
        three.extend_from_slice(state_after.as_slice());
        three.extend_from_slice(batch_output.as_slice());
        assert_eq!(
            batch_public_input_hash(&state_before, &state_after, None, &batch_output),
            keccak256(&three),
        );

        let mut four = Vec::new();
        four.extend_from_slice(state_before.as_slice());
        four.extend_from_slice(state_after.as_slice());
        four.extend_from_slice(chain_config.as_slice());
        four.extend_from_slice(batch_output.as_slice());
        assert_eq!(
            batch_public_input_hash(
                &state_before,
                &state_after,
                Some(&chain_config),
                &batch_output,
            ),
            keccak256(&four),
        );

        assert_ne!(keccak256(&three), keccak256(&four));
    }

    /// The hardcoded empty-subtree table must reproduce the recurrence over the
    /// all-zero reserved leaf, mirroring native's
    /// `chain_batch_root_empty_hashes_match_recurrence`.
    #[test]
    fn chain_batch_root_empty_hashes_match_the_recurrence() {
        let derived = empty_subtree_hashes(B256::ZERO, CHAIN_BATCH_ROOT_TREE_HEIGHT);
        for (level, entry) in CHAIN_BATCH_ROOT_EMPTY_SUBTREE_HASHES.iter().enumerate() {
            assert_eq!(B256::from(*entry), derived[level], "level {level}");
        }
    }

    /// Native's own trace of the height-3 fold
    /// (`.../zk/post_tx_op/mod.rs`, `chain_batch_root_is_height3_merkle`):
    /// four live leaves, four reserved zero leaves.
    #[test]
    fn chain_batch_root_is_a_height_three_merkle_tree() {
        let a = B256::repeat_byte(1);
        let b = B256::repeat_byte(2);
        let c = B256::repeat_byte(3);
        let d = B256::repeat_byte(4);
        let z = B256::ZERO;

        // Independent recomputation with the last four leaves zero.
        let level1 = [
            keccak_compress(&a, &b),
            keccak_compress(&c, &d),
            keccak_compress(&z, &z),
            keccak_compress(&z, &z),
        ];
        let level2 = [
            keccak_compress(&level1[0], &level1[1]),
            keccak_compress(&level1[2], &level1[3]),
        ];
        assert_eq!(
            chain_batch_root(ChainBatchRootLayout::HeightThreeMerkle, &a, &b, &c, &d),
            keccak_compress(&level2[0], &level2[1]),
        );
    }

    /// A chain that runs no interop at all still moves to a different value:
    /// the tree adds three keccak calls on top of the two-preimage form, so the
    /// all-zero input is well defined, non-zero, and distinct from the earlier
    /// specs' root. There is no opt-out.
    #[test]
    fn chain_batch_root_layouts_never_coincide() {
        let z = B256::ZERO;
        let tree = chain_batch_root(ChainBatchRootLayout::HeightThreeMerkle, &z, &z, &z, &z);
        assert_ne!(tree, B256::ZERO);
        assert_ne!(
            tree,
            chain_batch_root(ChainBatchRootLayout::TwoPreimageKeccak, &z, &z, &z, &z),
        );

        let logs = B256::repeat_byte(0x11);
        let multichain = B256::repeat_byte(0x22);
        assert_ne!(
            chain_batch_root(
                ChainBatchRootLayout::HeightThreeMerkle,
                &logs,
                &multichain,
                &z,
                &z,
            ),
            chain_batch_root(
                ChainBatchRootLayout::TwoPreimageKeccak,
                &logs,
                &multichain,
                &z,
                &z,
            ),
        );
    }

    /// The two-preimage form is the plain keccak of the two roots, which is
    /// what the released v30 and v31 lines commit.
    #[test]
    fn two_preimage_chain_batch_root_hashes_the_two_roots() {
        let logs = B256::repeat_byte(0x11);
        let multichain = B256::repeat_byte(0x22);
        assert_eq!(
            chain_batch_root(
                ChainBatchRootLayout::TwoPreimageKeccak,
                &logs,
                &multichain,
                &B256::repeat_byte(0x33),
                &B256::repeat_byte(0x44),
            ),
            keccak_two(&logs, &multichain),
        );
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
