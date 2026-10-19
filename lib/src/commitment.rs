//! Batch commitment computation: Keccak-based hashing for state commitments,
//! batch output hashes, L2→L1 log merkle trees, DA commitments, and priority ops.

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
use crate::crypto::blake2s::Blake2s256;
use alloy_primitives::B256;
#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
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
// State commitment (Blake2s). On the ZiSK target these run on the `blake2sf`
// precompile through `crate::crypto::blake2s`: `block_hashes_blake` alone is
// 128 compressions per call over the 256-entry block-hash ring.
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
    B256::from_slice(&h.finalize())
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
    B256::from_slice(&h.finalize())
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

/// The chain-config preimage layout a spec commits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChainConfigLayout {
    /// AtlasV4: `(chain_id, fri_proof_verification_enabled, max_tx_gas_limit,
    /// pubdata_content)`.
    AtlasV4,
    /// AtlasV5 (ZKsync OS 0.6.0): the AtlasV4 words followed by
    /// `l1_tx_filtering_enabled` and `large_contracts_enabled`.
    AtlasV5,
}

/// The chain-config fields [`chain_config_hash`] commits.
#[derive(Clone, Copy, Debug)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub fri_proof_verification_enabled: bool,
    pub max_tx_gas_limit: u64,
    pub pubdata_content: u8,
    pub l1_tx_filtering_enabled: bool,
    pub large_contracts_enabled: bool,
}

impl ChainConfig {
    /// The chain config `input` commits: the chain id of the batch and the
    /// chain-config fields of its `BatchMeta`.
    pub fn of_batch(input: &crate::types::BatchInput) -> Self {
        let meta = &input.batch_meta;
        Self {
            chain_id: input.chain_id,
            fri_proof_verification_enabled: meta.fri_proof_verification_enabled,
            max_tx_gas_limit: meta.max_tx_gas_limit,
            pubdata_content: meta.pubdata_content,
            l1_tx_filtering_enabled: meta.l1_tx_filtering_enabled,
            large_contracts_enabled: meta.large_contracts_enabled,
        }
    }
}

/// Canonical keccak256 commitment to the chain config, matching zksync-os
/// `ChainConfig::hash` (zk_ee .../metadata/chain_config.rs) of the spec's
/// release. One 32-byte word per field, in [`ChainConfigLayout`] order:
///   chain_id (uint256 BE), fri_proof_verification_enabled (last byte 0/1),
///   max_tx_gas_limit (u64 BE, right-aligned), pubdata_content (last byte the
///   mode id), and from AtlasV5 l1_tx_filtering_enabled and
///   large_contracts_enabled (last byte 0/1 each). The AtlasV4 layout leaves
///   the two flags out.
///
/// era-contracts `ZKChainBase._getZKsyncOSChainConfigHash` holds the same
/// encoding, so L1 can gate the two proving lanes against each other.
pub fn chain_config_hash(layout: ChainConfigLayout, config: &ChainConfig) -> B256 {
    let flag_word = |flag: bool| {
        let mut word = [0u8; 32];
        word[31] = u8::from(flag);
        word
    };
    let mut data = Vec::with_capacity(192);
    let mut chain_id_word = [0u8; 32];
    chain_id_word[24..].copy_from_slice(&config.chain_id.to_be_bytes());
    data.extend_from_slice(&chain_id_word);
    data.extend_from_slice(&flag_word(config.fri_proof_verification_enabled));
    let mut max_tx_gas_limit_word = [0u8; 32];
    max_tx_gas_limit_word[24..].copy_from_slice(&config.max_tx_gas_limit.to_be_bytes());
    data.extend_from_slice(&max_tx_gas_limit_word);
    let mut pubdata_content_word = [0u8; 32];
    pubdata_content_word[31] = config.pubdata_content;
    data.extend_from_slice(&pubdata_content_word);
    if layout == ChainConfigLayout::AtlasV5 {
        data.extend_from_slice(&flag_word(config.l1_tx_filtering_enabled));
        data.extend_from_slice(&flag_word(config.large_contracts_enabled));
    }
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

/// Pubdata encoding version (native `PUBDATA_ENCODING_VERSION`). Every layout
/// starts with the shared two-byte envelope header `[version, mode]`, where the
/// mode byte is the `PubdataContent` discriminant selecting the payload.
const PUBDATA_ENCODING_VERSION: u8 = 3;

/// The pubdata a `LogsOnly` chain commits, derived from the guest's own L2→L1
/// log set instead of the unauthenticated witness blob.
///
/// Native writes one section per block (`write_pubdata`): the two-byte envelope
/// header, then `apply_logs_pubdata` — the log count as a 4-byte big-endian
/// integer, then every 88-byte log record. State diffs and message payloads are
/// neither committed nor published in this mode, so the whole blob is bytes the
/// guest already derives.
///
/// This does not extend to `FullPubdata`, where the payload also carries the
/// block hash, the timestamp and the storage diffs; deriving that means
/// modelling the whole storage-diff encoding, which the guest does not do.
pub fn logs_only_pubdata(logs_by_block: &[Vec<[u8; L2_TO_L1_LOG_SIZE]>]) -> Vec<u8> {
    let record_bytes: usize = logs_by_block.iter().map(|logs| logs.len()).sum::<usize>()
        * L2_TO_L1_LOG_SIZE;
    let mut pubdata = Vec::with_capacity(logs_by_block.len() * 6 + record_bytes);
    for logs in logs_by_block {
        pubdata.push(PUBDATA_ENCODING_VERSION);
        pubdata.push(crate::types::PUBDATA_CONTENT_LOGS_ONLY);
        pubdata.extend_from_slice(&(logs.len() as u32).to_be_bytes());
        for log in logs {
            pubdata.extend_from_slice(log);
        }
    }
    pubdata
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
/// - AtlasV4 onwards (`chain_config_hash = Some(..)`): four words, with the
///   chain-config commitment as the third.
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

    /// The batch public input holds three words, which is what
    /// `Executor._getBatchProofPublicInputZKsyncOS` hashes on the settlement
    /// layer and what zksync-os v0.3.2 `BatchPublicInput::hash` computes. A
    /// fourth `chain_config_hash` word arrives with the 0.4.0 line. The
    /// expected value comes from `cast keccak` over the concatenation, so the
    /// oracle is independent of this crate.
    #[test]
    fn batch_public_input_holds_three_words() {
        let state_before = B256::repeat_byte(0x11);
        let state_after = B256::repeat_byte(0x22);
        let batch_output = B256::repeat_byte(0x33);
        let expected: B256 = "0x41524791bda53e6da2158f10c15e3672835515d6135111d11c7e9880cfcbe573"
            .parse()
            .unwrap();
        assert_eq!(
            batch_public_input_hash(&state_before, &state_after, None, &batch_output),
            expected,
        );
    }

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

    /// The chain config of native's golden vectors
    /// (`.../zk/post_tx_op/public_input.rs`, `sample_chain_config`): chain id
    /// 37, FRI proof verification disabled, the EIP-7825 default
    /// per-transaction gas cap, full pubdata, and both 0.6.0 flags off.
    fn sample_chain_config() -> ChainConfig {
        ChainConfig {
            chain_id: 37,
            fri_proof_verification_enabled: false,
            max_tx_gas_limit: 1 << 24,
            pubdata_content: 0,
            l1_tx_filtering_enabled: false,
            large_contracts_enabled: false,
        }
    }

    /// The batch output of native's `BATCH_OUTPUT_HASH_GOLDEN`, as in
    /// `atlas_v4_batch_output_matches_the_native_golden_vector`.
    fn sample_batch_output() -> B256 {
        batch_output_hash_native(
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
        )
    }

    /// The public input over zero state commitments that native's golden
    /// vectors hash.
    fn sample_public_input(layout: ChainConfigLayout, config: &ChainConfig) -> B256 {
        batch_public_input_hash(
            &B256::ZERO,
            &B256::ZERO,
            Some(&chain_config_hash(layout, config)),
            &sample_batch_output(),
        )
    }

    /// Native 0.5.x's golden vectors for `ChainConfig::hash` and the whole
    /// batch public input (`chain_config_hash_golden_vector`,
    /// `batch_public_input_hash_golden_vector` at zksync-os v0.5.6).
    #[test]
    fn atlas_v4_chain_config_matches_the_native_golden_vectors() {
        let config = sample_chain_config();
        let expected_config: B256 =
            "0x9bba8b838beaad59a5dec253b49be1f496d47df8c2086b561298cae2cc232c0a"
                .parse()
                .unwrap();
        let expected_public_input: B256 =
            "0x0a5143e28ed3fc1728ef4d96319f2306bb5a81bfccd908154e44029988ef9e7c"
                .parse()
                .unwrap();
        assert_eq!(
            chain_config_hash(ChainConfigLayout::AtlasV4, &config),
            expected_config
        );
        assert_eq!(
            sample_public_input(ChainConfigLayout::AtlasV4, &config),
            expected_public_input
        );
    }

    /// Native 0.6.0's golden vectors (`chain_config_hash_golden_vector`,
    /// `batch_public_input_hash_golden_vector` and
    /// `batch_public_input_hash_flag_golden_vectors` on `draft-0.6.0`). The
    /// asymmetric flag pairs pin which flag takes which word. era-contracts
    /// `TestConstants.sol` (`PUBLIC_INPUT_HASH_GOLDEN*`) pins the same public
    /// inputs.
    #[test]
    fn atlas_v5_chain_config_matches_the_native_golden_vectors() {
        for (filtering, large_contracts, expected_config, expected_public_input) in [
            (
                false,
                false,
                "0xa37baa17e852b9c326cea601ab0565fb733b0e0c4590f5a39efc8da5e3ec485c",
                "0x115e07747f99e4785e3f1c91d3ff85f05eee22c99004e6a81adc37b1b21495fe",
            ),
            (
                true,
                false,
                "0xf376cdd377febdda64444c8e0ba5b368ebb3347f597404ffa51a6c19299479c2",
                "0x7bb4bea265b944d45623d3e57de083aceb9c7d9f30240c3a917fa187a4444282",
            ),
            (
                false,
                true,
                "0x7431a77ce6e77c295d5f7e097382054ac118b993f7b311c765a41f744e99d448",
                "0xac58d82a0990197b31c12ec9cc33b330e5dbda74011eafd37b7e78a5241f0ec7",
            ),
            (
                true,
                true,
                "0xd8fab3201bc811330f9f0f5d5a68ed7c30713d11d513da418f93c59f01cd2a0c",
                "0xa78ab15446de058e9f871114c4b0333d8ab23ec8959f89b582c33409751aa837",
            ),
        ] {
            let config = ChainConfig {
                l1_tx_filtering_enabled: filtering,
                large_contracts_enabled: large_contracts,
                ..sample_chain_config()
            };
            assert_eq!(
                chain_config_hash(ChainConfigLayout::AtlasV5, &config),
                expected_config.parse::<B256>().unwrap(),
                "filtering={filtering} large_contracts={large_contracts}",
            );
            assert_eq!(
                sample_public_input(ChainConfigLayout::AtlasV5, &config),
                expected_public_input.parse::<B256>().unwrap(),
                "filtering={filtering} large_contracts={large_contracts}",
            );
        }
    }

    /// Every chain-config word reaches the commitment, so a change in any one
    /// of them moves the hash. Native pins the same property per field
    /// (`batch_public_input_hash_commits_to_*`). The AtlasV4 layout has no
    /// flag words, so the flags leave its hash alone.
    #[test]
    fn chain_config_commits_to_every_word() {
        let base = sample_chain_config();
        let variants = [
            ChainConfig { chain_id: 38, ..base },
            ChainConfig { fri_proof_verification_enabled: true, ..base },
            ChainConfig { max_tx_gas_limit: 1 << 25, ..base },
            ChainConfig { pubdata_content: 1, ..base },
        ];
        for layout in [ChainConfigLayout::AtlasV4, ChainConfigLayout::AtlasV5] {
            for variant in &variants {
                assert_ne!(
                    chain_config_hash(layout, &base),
                    chain_config_hash(layout, variant),
                    "{layout:?} {variant:?}",
                );
            }
        }
        for flags in [
            ChainConfig { l1_tx_filtering_enabled: true, ..base },
            ChainConfig { large_contracts_enabled: true, ..base },
        ] {
            assert_ne!(
                chain_config_hash(ChainConfigLayout::AtlasV5, &base),
                chain_config_hash(ChainConfigLayout::AtlasV5, &flags),
            );
            assert_eq!(
                chain_config_hash(ChainConfigLayout::AtlasV4, &base),
                chain_config_hash(ChainConfigLayout::AtlasV4, &flags),
            );
        }
        assert_ne!(
            chain_config_hash(ChainConfigLayout::AtlasV4, &base),
            chain_config_hash(ChainConfigLayout::AtlasV5, &base),
        );
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

    /// The logs-only blob is one section per block: the two-byte envelope
    /// header, the 4-byte big-endian log count, then every 88-byte record.
    #[test]
    fn logs_only_pubdata_is_the_header_and_the_log_records() {
        let first = [0x11u8; L2_TO_L1_LOG_SIZE];
        let second = [0x22u8; L2_TO_L1_LOG_SIZE];
        let pubdata = logs_only_pubdata(&[vec![first, second], vec![]]);

        let mut expected = vec![3u8, 1, 0, 0, 0, 2];
        expected.extend_from_slice(&first);
        expected.extend_from_slice(&second);
        expected.extend_from_slice(&[3u8, 1, 0, 0, 0, 0]);
        assert_eq!(pubdata, expected);
    }

    /// A block with no logs still writes its envelope header and a zero count,
    /// so an empty batch commits six bytes per block rather than nothing.
    #[test]
    fn logs_only_pubdata_of_an_empty_block_is_the_header_and_a_zero_count() {
        assert_eq!(logs_only_pubdata(&[vec![]]), vec![3u8, 1, 0, 0, 0, 0]);
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
