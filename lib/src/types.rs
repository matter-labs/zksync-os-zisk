//! Shared types for ZiSK guest/host communication.

use revm::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// Current `BatchInput` wire-format version.
///
/// **v5**: ZKsync OS 0.5.0 semantics under AtlasV4. `BatchMeta` carries the
/// chain-config `pubdata_content` mode (the fourth word of
/// `chain_config_hash`), and `BatchMeta.interop_proofs` carries the four
/// interop commitment tree (`0x10012`) slot proofs the chain batch root needs.
///
/// **v4**: AtlasV4 support. The struct layout is unchanged, but the
/// input-builder contract is not: an AtlasV4 block must carry the EIP-2935
/// history contract's account preimage, its account-properties proof, and a
/// proof of the history slot the block writes. The bump makes an old server
/// paired with a new guest fail with the named version error rather than a
/// missing-proof panic.
///
/// **v3**: adds `BatchMeta.interop_proofs` — authenticated storage proofs that
/// let the guest DERIVE `sl_chain_id` (SystemContext `0x800b` slot 0, post-state)
/// and `multichain_root` (MessageRoot `0x10005` aggregation slots, post-state)
/// instead of trusting the witness scalars. See `executor::interop`.
///
/// **v2**: adds `TxAuth::System` (system transactions — interop
/// root imports, SL-chain-id updates, interop fee updates — carried as their
/// EIP-2718 encoding and authenticated by `keccak256(encoded) == tx_hash`).
/// v1 is otherwise unchanged. The wire format is bincode 2.x through its serde
/// path, standard configuration (non-self-describing, positional, little-endian,
/// variable-length integers) over the structs in this module (see
/// `crate::wire`), framed for the ZiSK guest as
/// `[len: u64 LE][bincode][zero pad to 8]`. Every field is required; there
/// are no optional-at-the-wire fields.
///
/// Compatibility rule: the server (input builder), the guest ELF, and the
/// prover service must be built from the same revision of this crate. Any
/// change to the layout of `BatchInput` or anything it transitively contains
/// bumps this constant in the same commit; the executor rejects versions it
/// does not understand before touching the rest of the payload, so a skew
/// fails with a named error instead of a positional misparse. A version bump
/// implies a guest rebuild and therefore a VK rotation.
pub const BATCH_INPUT_VERSION: u32 = 5;

use crate::merkle::{BatchTreeUpdate, StorageProof};

/// Authenticated storage proofs for the interop-derived batch scalars.
///
/// Native zksync-os obtains `multichain_root` and `sl_chain_id` as authenticated
/// storage reads of fixed system-contract slots at batch boundaries, NOT as
/// functions of the batch's own logs (see
/// `basic_bootloader block_flow/zk/post_tx_op` `read_batch_context_inputs`). The
/// guest's `ProvenDB` only serves slots the server proved during execution, so
/// these three proofs are supplied explicitly and the guest reproduces the
/// native reads in `executor::interop`, replacing the untrusted witness scalars.
///
/// Present (required) for v31+ batches; `None` for v30 (which uses neither
/// value in its commitment).
#[derive(Serialize, Deserialize, Clone)]
pub struct InteropSlotProofs {
    /// Proof of SystemContext (`0x800b`) slot 0 — the settlement-layer chain id
    /// — against `tree_root_after`. Post-state is used for every batch: an
    /// upgrade batch may write this slot during the batch, and the post-state
    /// read observes that write. `Existing` ⇒ the stored chain id;
    /// `NonExisting` ⇒ 0.
    pub sl_chain_id: StorageProof,
    /// Proof of MessageRoot (`0x10005`) slot `0x04` — the aggregation-tree
    /// height — against `tree_root_after`. `NonExisting` ⇒ height 0.
    pub multichain_height: StorageProof,
    /// Proof of MessageRoot (`0x10005`) slot `nodes[height][0]` — the multichain
    /// root — against `tree_root_after`. The slot is derived in-guest from the
    /// height read above; `NonExisting` ⇒ root 0 (chain is not a settlement
    /// layer).
    pub multichain_root: StorageProof,
    /// Proofs of the interop commitment tree root at both batch boundaries.
    /// Required for AtlasV4 batches, whose chain batch root carries both roots
    /// as leaves; `None` for the earlier specs, which commit neither.
    pub commitment_tree: Option<InteropCommitmentTreeProofs>,
}

/// Authenticated storage proofs for the interop commitment tree (`0x10012`)
/// root at the two batch boundaries.
///
/// Native reads the tree height (slot 0) and then `_nodes[height][0]` before
/// the batch's first block and again after its last block
/// (`block_flow/zk/pre_tx_loop` and
/// `.../post_tx_op::read_interop_commitment_tree_root`). Both roots are leaves
/// of the chain batch root, so the guest reproduces both reads against the two
/// state roots it already pins.
#[derive(Serialize, Deserialize, Clone)]
pub struct InteropCommitmentTreeProofs {
    /// Proof of `0x10012` slot 0 — the tree height — against
    /// `tree_root_before`. `NonExisting` ⇒ height 0.
    pub height_begin: StorageProof,
    /// Proof of `0x10012` slot `_nodes[height][0]` against `tree_root_before`.
    /// The slot is derived in-guest from the height read above; `NonExisting`
    /// ⇒ root 0 (the chain has no commitment tree deployed).
    pub root_begin: StorageProof,
    /// Proof of `0x10012` slot 0 against `tree_root_after`.
    pub height_end: StorageProof,
    /// Proof of `0x10012` slot `_nodes[height][0]` against `tree_root_after`.
    pub root_end: StorageProof,
}

/// `PubdataContent::FullPubdata`: the batch commits the block hash, the
/// timestamp, the storage diffs, the L2→L1 log records and the message
/// payloads.
pub const PUBDATA_CONTENT_FULL: u8 = 0;

/// `PubdataContent::LogsOnly`: the batch commits the mandatory L2→L1 log
/// records alone. Storage diffs and message payloads stay off the DA
/// commitment.
pub const PUBDATA_CONTENT_LOGS_ONLY: u8 = 1;

/// Complete batch input for the ZiSK guest.
#[derive(Serialize, Deserialize, Clone)]
pub struct BatchInput {
    /// Wire-format version. Bump on any layout change; the executor rejects
    /// versions it does not understand. Leading field so future decoders can
    /// read it before the rest of the payload.
    pub version: u32,
    pub chain_id: u64,
    /// ZKsync OS state transition function tier: AtlasV1 = 0, AtlasV2 = 1,
    /// AtlasV3 = 2, AtlasV4 = 3. This is the single source of truth for every
    /// version-dependent formula the guest computes.
    pub spec_id: u8,
    /// L1 protocol version minor. Cross-checked against `spec_id` for
    /// consistency; it selects no formula of its own.
    pub protocol_version_minor: u32,
    pub blocks: Vec<BlockInput>,
    /// Batch-level metadata for commitment computation.
    pub batch_meta: BatchMeta,
    /// Contract bytecodes keyed by code hash (keccak256).
    /// Shared across all blocks in the batch.
    pub bytecodes: Vec<(B256, Vec<u8>)>,
}

/// Batch-level metadata needed for the commitment hash.
#[derive(Serialize, Deserialize, Clone)]
pub struct BatchMeta {
    /// Merkle tree root hash before this batch.
    pub tree_root_before: B256,
    /// Leaf count before this batch (includes 2 guard entries).
    pub leaf_count_before: u64,
    /// Block number before this batch.
    pub block_number_before: u64,
    /// Last block timestamp before batch.
    pub last_block_timestamp_before: u64,
    /// Blake2s hash of last 256 block hashes before this batch.
    /// This is part of the state commitment preimage and should be taken
    /// from the verified state commitment (e.g. via zks_getProof).
    pub block_hashes_blake_before: B256,
    /// Previous 255 block hashes (index 1..255 of the block_hashes array).
    pub previous_block_hashes: Vec<B256>,
    /// Upgrade tx hash if present (zero otherwise).
    pub upgrade_tx_hash: B256,
    /// DA commitment scheme (0=None, 1=EmptyNoDA, 2=PubdataKeccak, 3=BlobsAndPubdataKeccak, 4=BlobsZKsyncOS).
    pub da_commitment_scheme: u8,
    /// Raw pubdata bytes for DA commitment computation.
    pub pubdata: Vec<u8>,
    /// Multichain root for L2 logs tree (zero for v30).
    ///
    /// Legacy witness scalar. For v31+ the guest no longer trusts this value;
    /// it derives the authoritative multichain root from `interop_proofs`
    /// (`executor::interop`). Retained on the wire for the server's own use.
    pub multichain_root: B256,
    /// Settlement layer chain ID (for v31+).
    ///
    /// Legacy witness scalar. For every v31+ batch the guest derives the
    /// authoritative value from `interop_proofs` instead of trusting this field.
    pub sl_chain_id: u64,
    /// Blob versioned hashes for BlobsZKsyncOS DA mode (scheme=4).
    /// The host computes KZG commitments of the pubdata blobs and derives
    /// versioned hashes. The guest uses these to compute da_commitment =
    /// keccak256(versioned_hashes). KZG correctness is verified by L1 (EIP-4844).
    pub blob_versioned_hashes: Vec<B256>,
    /// Merkle tree update proof for computing state_after root.
    /// Contains old leaves, intermediate hashes, and write operations.
    /// If None, state_after root = state_before root (no writes — incomplete).
    pub tree_update: Option<BatchTreeUpdate>,
    /// After-state account property preimages (124 bytes each).
    /// For each account whose 0x8003 value changed, the server provides the
    /// full after-state preimage. The executor verifies nonce/balance match
    /// REVM's output, then checks blake2s(preimage) == tree_update value.
    pub account_preimages_after: Vec<(Address, Vec<u8>)>,
    /// Chain-config inputs committed into the batch public input via
    /// `chain_config_hash` (zksync-os `ChainConfig::hash`).
    /// `fri_proof_verification_enabled`, `max_tx_gas_limit` and
    /// `pubdata_content` are not otherwise present in the batch; `chain_id` is
    /// taken from `BatchInput::chain_id`.
    pub fri_proof_verification_enabled: bool,
    pub max_tx_gas_limit: u64,
    /// Which part of the pubdata the chain commits, as the native
    /// `PubdataContent` discriminant ([`PUBDATA_CONTENT_FULL`] or
    /// [`PUBDATA_CONTENT_LOGS_ONLY`]). The executor rejects any other value.
    pub pubdata_content: u8,
    /// Authenticated proofs for the interop-derived scalars (`sl_chain_id`,
    /// `multichain_root`). Required for v31+ batches; `None` for v30.
    pub interop_proofs: Option<InteropSlotProofs>,
}

/// Single block input with pre-state and transactions.
#[derive(Serialize, Deserialize, Clone)]
pub struct BlockInput {
    pub number: u64,
    pub timestamp: u64,
    pub base_fee: u64,
    pub gas_limit: u64,
    pub coinbase: Address,
    pub prev_randao: B256,
    pub transactions: Vec<TxInput>,
    /// Account property preimages (124-byte encoded AccountProperties).
    /// Keyed by address. Used to decode nonce/balance/code_hash from the
    /// merkle-verified value at (0x8003, left_padded_address).
    pub account_preimages: Vec<(Address, Vec<u8>)>,
    /// Block hashes for BLOCKHASH opcode.
    pub block_hashes: Vec<(u64, B256)>,
    /// Merkle proofs for every storage slot accessed. Key = flat_storage_key.
    pub storage_proofs: Vec<(B256, StorageProof)>,
    /// Canonical hash of this block's header as sealed by the server.
    /// When non-zero, the guest asserts its recomputed header hash matches,
    /// failing re-execution loudly on any header drift.
    pub block_header_hash: B256,
    /// L2→L1 logs produced by this block's execution (from server's BlockOutput).
    ///
    /// Witness data the commitment path does not read: the guest derives its own
    /// L2→L1 log set from the REVM journal and folds that into the logs merkle
    /// tree (`executor::evm`). Comparing two guest-derived sets authenticates
    /// nothing, so this field is retained for the server's own use only.
    pub l2_to_l1_logs: Vec<L2ToL1LogEntry>,
    /// Per-block tree root that this block's merkle proofs were extracted from.
    /// For the first block in a batch this equals batch_meta.tree_root_before.
    /// For subsequent blocks this is the tree root after prior blocks' writes.
    pub expected_tree_root: B256,
}

/// Transaction authentication and hash binding.
///
/// Each variant carries the raw bytes from which all execution fields are
/// derived. The executor verifies and extracts:
/// - L1/Upgrade: `keccak256(abi_encoded) == tx_hash`, then decodes all fields from ABI
/// - L2: `ecrecover(signed_bytes)` recovers caller, all fields decoded from RLP
#[derive(Serialize, Deserialize, Clone)]
pub enum TxAuth {
    /// L1 priority deposit. `abi_encoded` is the ABI-encoded L2CanonicalTransaction
    /// whose `keccak256` equals `tx_hash`. All execution fields are extracted from it.
    L1 { tx_hash: B256, abi_encoded: Vec<u8> },
    /// Protocol upgrade transaction. Same ABI encoding as L1.
    Upgrade { tx_hash: B256, abi_encoded: Vec<u8> },
    /// L2 transaction. `signed_bytes` is EIP-2718 encoded; all execution fields
    /// are decoded from the RLP envelope, caller recovered via ecrecover.
    L2 { signed_bytes: Vec<u8> },
    /// Protocol-injected system transaction (interop root import, SL-chain-id
    /// update, interop fee update). `encoded_2718` is
    /// `0x7d ‖ rlp([to, input, salt])` whose `keccak256` equals `tx_hash`;
    /// execution fields are decoded from it. The caller is always the
    /// bootloader formal address (a protocol constant, not witness data).
    System { tx_hash: B256, encoded_2718: Vec<u8> },
}

/// Transaction input for the ZiSK executor.
///
/// Execution-critical fields (caller, to, value, data, nonce, gas_limit,
/// gas_price) are derived from the authenticated `auth` data — NOT from
/// this struct. Only `chain_id` (for L1/upgrade, not in ABI),
/// `gas_used_override`, and `force_fail` are used from here.
#[derive(Serialize, Deserialize, Clone)]
pub struct TxInput {
    /// L2 chain ID. Used for L1/upgrade txs (not present in ABI encoding)
    /// and as fallback for L2 txs without chain_id in the envelope.
    pub chain_id: Option<u64>,
    /// Gas used override from the server's execution.
    /// When set, REVM uses this instead of its own gas computation.
    pub gas_used_override: Option<u64>,
    /// When true, REVM synthesizes a REVERT without executing the transaction.
    pub force_fail: bool,
    /// Transaction authentication and hash binding.
    /// All execution fields are derived from this.
    pub auth: TxAuth,
}

/// L2->L1 log entry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct L2ToL1LogEntry {
    pub l2_shard_id: u8,
    pub is_service: bool,
    pub tx_number_in_block: u16,
    pub sender: Address,
    pub key: B256,
    pub value: B256,
}

impl L2ToL1LogEntry {
    /// Encode to 88 bytes matching server's L2ToL1Log::encode.
    pub fn encode(&self) -> [u8; 88] {
        let mut buf = [0u8; 88];
        buf[0] = self.l2_shard_id;
        buf[1] = if self.is_service { 1 } else { 0 };
        buf[2..4].copy_from_slice(&self.tx_number_in_block.to_be_bytes());
        buf[4..24].copy_from_slice(self.sender.as_slice());
        buf[24..56].copy_from_slice(self.key.as_slice());
        buf[56..88].copy_from_slice(self.value.as_slice());
        buf
    }
}

#[derive(Serialize, Deserialize)]
pub struct BatchOutput {
    pub chain_id: u64,
    pub block_results: Vec<BlockResult>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockResult {
    pub block_number: u64,
    /// Block header hash computed from execution results.
    /// keccak256(RLP(parent_hash, ommers_hash, beneficiary, state_root=0,
    ///   transactions_root, receipts_root=0, logs_bloom=0, difficulty=0,
    ///   number, gas_limit, gas_used, timestamp, extra_data=[], mix_hash,
    ///   nonce=0, base_fee_per_gas))
    pub computed_block_header_hash: B256,
    pub tx_results: Vec<TxOutput>,
    pub l2_to_l1_logs: Vec<L2ToL1LogEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct TxOutput {
    pub success: bool,
    pub gas_used: u64,
    pub output: Vec<u8>,
}

