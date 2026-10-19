//! Frozen schema for released `BatchInput` wire version 3.
//!
//! Do not change field order, field types, or enum variant order in this
//! module. New execution code decodes these types and converts them into the
//! current representation; producers that intentionally need a durable v3
//! fixture may also construct and serialize them directly.

use revm::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// The released wire version represented by this module.
pub const BATCH_INPUT_VERSION: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotProofEntry {
    pub index: u64,
    pub value: B256,
    pub next_index: u64,
    pub siblings: Vec<B256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageProof {
    Existing(SlotProofEntry),
    NonExisting {
        left_neighbor: NeighborProofEntry,
        right_neighbor: NeighborProofEntry,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborProofEntry {
    pub entry: SlotProofEntry,
    pub leaf_key: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeLeaf {
    pub key: B256,
    pub value: B256,
    pub next_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WriteOp {
    Update { index: u64 },
    Insert { prev_index: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTreeUpdate {
    pub operations: Vec<WriteOp>,
    pub entries: Vec<(B256, B256)>,
    pub sorted_leaves: Vec<(u64, TreeLeaf)>,
    pub intermediate_hashes: Vec<B256>,
    pub leaf_count_before: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InteropSlotProofs {
    pub sl_chain_id: StorageProof,
    pub multichain_height: StorageProof,
    pub multichain_root: StorageProof,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BatchInput {
    pub version: u32,
    pub chain_id: u64,
    pub spec_id: u8,
    pub protocol_version_minor: u32,
    pub blocks: Vec<BlockInput>,
    pub batch_meta: BatchMeta,
    pub bytecodes: Vec<(B256, Vec<u8>)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BatchMeta {
    pub tree_root_before: B256,
    pub leaf_count_before: u64,
    pub block_number_before: u64,
    pub last_block_timestamp_before: u64,
    pub block_hashes_blake_before: B256,
    pub previous_block_hashes: Vec<B256>,
    pub upgrade_tx_hash: B256,
    pub da_commitment_scheme: u8,
    pub pubdata: Vec<u8>,
    pub multichain_root: B256,
    pub sl_chain_id: u64,
    pub blob_versioned_hashes: Vec<B256>,
    pub tree_update: Option<BatchTreeUpdate>,
    pub account_preimages_after: Vec<(Address, Vec<u8>)>,
    pub fri_proof_verification_enabled: bool,
    pub max_tx_gas_limit: u64,
    pub interop_proofs: Option<InteropSlotProofs>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockInput {
    pub number: u64,
    pub timestamp: u64,
    pub base_fee: u64,
    pub gas_limit: u64,
    pub coinbase: Address,
    pub prev_randao: B256,
    pub transactions: Vec<TxInput>,
    pub account_preimages: Vec<(Address, Vec<u8>)>,
    pub block_hashes: Vec<(u64, B256)>,
    pub storage_proofs: Vec<(B256, StorageProof)>,
    pub block_header_hash: B256,
    pub l2_to_l1_logs: Vec<L2ToL1LogEntry>,
    pub expected_tree_root: B256,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum TxAuth {
    L1 {
        tx_hash: B256,
        abi_encoded: Vec<u8>,
    },
    Upgrade {
        tx_hash: B256,
        abi_encoded: Vec<u8>,
    },
    L2 {
        signed_bytes: Vec<u8>,
    },
    System {
        tx_hash: B256,
        encoded_2718: Vec<u8>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub chain_id: Option<u64>,
    pub gas_used_override: Option<u64>,
    pub force_fail: bool,
    pub auth: TxAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2ToL1LogEntry {
    pub l2_shard_id: u8,
    pub is_service: bool,
    pub tx_number_in_block: u16,
    pub sender: Address,
    pub key: B256,
    pub value: B256,
}

/// A current in-memory input cannot be represented on wire v3 when it uses a
/// field or spec introduced after that release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionError {
    UnsupportedSpec(u8),
    UnsupportedPubdataContent(u8),
    InteropCommitmentTree,
}

impl core::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedSpec(spec_id) => {
                write!(f, "wire v3 cannot represent spec_id {spec_id}")
            }
            Self::UnsupportedPubdataContent(mode) => {
                write!(f, "wire v3 cannot represent pubdata_content {mode}")
            }
            Self::InteropCommitmentTree => {
                f.write_str("wire v3 cannot represent interop commitment-tree proofs")
            }
        }
    }
}

impl std::error::Error for ConversionError {}

impl From<SlotProofEntry> for crate::merkle::SlotProofEntry {
    fn from(value: SlotProofEntry) -> Self {
        Self {
            index: value.index,
            value: value.value,
            next_index: value.next_index,
            siblings: value.siblings,
        }
    }
}

impl From<StorageProof> for crate::merkle::StorageProof {
    fn from(value: StorageProof) -> Self {
        match value {
            StorageProof::Existing(entry) => Self::Existing(entry.into()),
            StorageProof::NonExisting {
                left_neighbor,
                right_neighbor,
            } => Self::NonExisting {
                left_neighbor: left_neighbor.into(),
                right_neighbor: right_neighbor.into(),
            },
        }
    }
}

impl From<NeighborProofEntry> for crate::merkle::NeighborProofEntry {
    fn from(value: NeighborProofEntry) -> Self {
        Self {
            entry: value.entry.into(),
            leaf_key: value.leaf_key,
        }
    }
}

impl From<TreeLeaf> for crate::merkle::TreeLeaf {
    fn from(value: TreeLeaf) -> Self {
        Self {
            key: value.key,
            value: value.value,
            next_index: value.next_index,
        }
    }
}

impl From<WriteOp> for crate::merkle::WriteOp {
    fn from(value: WriteOp) -> Self {
        match value {
            WriteOp::Update { index } => Self::Update { index },
            WriteOp::Insert { prev_index } => Self::Insert { prev_index },
        }
    }
}

impl From<BatchTreeUpdate> for crate::merkle::BatchTreeUpdate {
    fn from(value: BatchTreeUpdate) -> Self {
        Self {
            operations: value.operations.into_iter().map(Into::into).collect(),
            entries: value.entries,
            sorted_leaves: value
                .sorted_leaves
                .into_iter()
                .map(|(index, leaf)| (index, leaf.into()))
                .collect(),
            intermediate_hashes: value.intermediate_hashes,
            leaf_count_before: value.leaf_count_before,
        }
    }
}

impl From<InteropSlotProofs> for crate::types::InteropSlotProofs {
    fn from(value: InteropSlotProofs) -> Self {
        Self {
            sl_chain_id: value.sl_chain_id.into(),
            multichain_height: value.multichain_height.into(),
            multichain_root: value.multichain_root.into(),
            commitment_tree: None,
        }
    }
}

impl From<TxAuth> for crate::types::TxAuth {
    fn from(value: TxAuth) -> Self {
        match value {
            TxAuth::L1 {
                tx_hash,
                abi_encoded,
            } => Self::L1 {
                tx_hash,
                abi_encoded,
            },
            TxAuth::Upgrade {
                tx_hash,
                abi_encoded,
            } => Self::Upgrade {
                tx_hash,
                abi_encoded,
            },
            TxAuth::L2 { signed_bytes } => Self::L2 { signed_bytes },
            TxAuth::System {
                tx_hash,
                encoded_2718,
            } => Self::System {
                tx_hash,
                encoded_2718,
            },
        }
    }
}

impl From<TxInput> for crate::types::TxInput {
    fn from(value: TxInput) -> Self {
        Self {
            chain_id: value.chain_id,
            gas_used_override: value.gas_used_override,
            force_fail: value.force_fail,
            auth: value.auth.into(),
        }
    }
}

impl From<L2ToL1LogEntry> for crate::types::L2ToL1LogEntry {
    fn from(value: L2ToL1LogEntry) -> Self {
        Self {
            l2_shard_id: value.l2_shard_id,
            is_service: value.is_service,
            tx_number_in_block: value.tx_number_in_block,
            sender: value.sender,
            key: value.key,
            value: value.value,
        }
    }
}

impl From<BlockInput> for crate::types::BlockInput {
    fn from(value: BlockInput) -> Self {
        Self {
            number: value.number,
            timestamp: value.timestamp,
            base_fee: value.base_fee,
            gas_limit: value.gas_limit,
            coinbase: value.coinbase,
            prev_randao: value.prev_randao,
            transactions: value.transactions.into_iter().map(Into::into).collect(),
            account_preimages: value.account_preimages,
            block_hashes: value.block_hashes,
            storage_proofs: value
                .storage_proofs
                .into_iter()
                .map(|(key, proof)| (key, proof.into()))
                .collect(),
            block_header_hash: value.block_header_hash,
            l2_to_l1_logs: value.l2_to_l1_logs.into_iter().map(Into::into).collect(),
            expected_tree_root: value.expected_tree_root,
        }
    }
}

impl From<BatchMeta> for crate::types::BatchMeta {
    fn from(value: BatchMeta) -> Self {
        Self {
            tree_root_before: value.tree_root_before,
            leaf_count_before: value.leaf_count_before,
            block_number_before: value.block_number_before,
            last_block_timestamp_before: value.last_block_timestamp_before,
            block_hashes_blake_before: value.block_hashes_blake_before,
            previous_block_hashes: value.previous_block_hashes,
            upgrade_tx_hash: value.upgrade_tx_hash,
            da_commitment_scheme: value.da_commitment_scheme,
            pubdata: value.pubdata,
            multichain_root: value.multichain_root,
            sl_chain_id: value.sl_chain_id,
            blob_versioned_hashes: value.blob_versioned_hashes,
            tree_update: value.tree_update.map(Into::into),
            account_preimages_after: value.account_preimages_after,
            fri_proof_verification_enabled: value.fri_proof_verification_enabled,
            max_tx_gas_limit: value.max_tx_gas_limit,
            pubdata_content: crate::types::PUBDATA_CONTENT_FULL,
            l1_tx_filtering_enabled: false,
            large_contracts_enabled: false,
            interop_proofs: value.interop_proofs.map(Into::into),
        }
    }
}

impl From<BatchInput> for crate::types::BatchInput {
    fn from(value: BatchInput) -> Self {
        Self {
            version: value.version,
            chain_id: value.chain_id,
            spec_id: value.spec_id,
            protocol_version_minor: value.protocol_version_minor,
            blocks: value.blocks.into_iter().map(Into::into).collect(),
            batch_meta: value.batch_meta.into(),
            bytecodes: value.bytecodes,
        }
    }
}

impl From<crate::merkle::SlotProofEntry> for SlotProofEntry {
    fn from(value: crate::merkle::SlotProofEntry) -> Self {
        Self {
            index: value.index,
            value: value.value,
            next_index: value.next_index,
            siblings: value.siblings,
        }
    }
}

impl From<crate::merkle::StorageProof> for StorageProof {
    fn from(value: crate::merkle::StorageProof) -> Self {
        match value {
            crate::merkle::StorageProof::Existing(entry) => Self::Existing(entry.into()),
            crate::merkle::StorageProof::NonExisting {
                left_neighbor,
                right_neighbor,
            } => Self::NonExisting {
                left_neighbor: left_neighbor.into(),
                right_neighbor: right_neighbor.into(),
            },
        }
    }
}

impl From<crate::merkle::NeighborProofEntry> for NeighborProofEntry {
    fn from(value: crate::merkle::NeighborProofEntry) -> Self {
        Self {
            entry: value.entry.into(),
            leaf_key: value.leaf_key,
        }
    }
}

impl From<crate::merkle::TreeLeaf> for TreeLeaf {
    fn from(value: crate::merkle::TreeLeaf) -> Self {
        Self {
            key: value.key,
            value: value.value,
            next_index: value.next_index,
        }
    }
}

impl From<crate::merkle::WriteOp> for WriteOp {
    fn from(value: crate::merkle::WriteOp) -> Self {
        match value {
            crate::merkle::WriteOp::Update { index } => Self::Update { index },
            crate::merkle::WriteOp::Insert { prev_index } => Self::Insert { prev_index },
        }
    }
}

impl From<crate::merkle::BatchTreeUpdate> for BatchTreeUpdate {
    fn from(value: crate::merkle::BatchTreeUpdate) -> Self {
        Self {
            operations: value.operations.into_iter().map(Into::into).collect(),
            entries: value.entries,
            sorted_leaves: value
                .sorted_leaves
                .into_iter()
                .map(|(index, leaf)| (index, leaf.into()))
                .collect(),
            intermediate_hashes: value.intermediate_hashes,
            leaf_count_before: value.leaf_count_before,
        }
    }
}

impl TryFrom<crate::types::InteropSlotProofs> for InteropSlotProofs {
    type Error = ConversionError;

    fn try_from(value: crate::types::InteropSlotProofs) -> Result<Self, Self::Error> {
        if value.commitment_tree.is_some() {
            return Err(ConversionError::InteropCommitmentTree);
        }
        Ok(Self {
            sl_chain_id: value.sl_chain_id.into(),
            multichain_height: value.multichain_height.into(),
            multichain_root: value.multichain_root.into(),
        })
    }
}

impl From<crate::types::TxAuth> for TxAuth {
    fn from(value: crate::types::TxAuth) -> Self {
        match value {
            crate::types::TxAuth::L1 {
                tx_hash,
                abi_encoded,
            } => Self::L1 {
                tx_hash,
                abi_encoded,
            },
            crate::types::TxAuth::Upgrade {
                tx_hash,
                abi_encoded,
            } => Self::Upgrade {
                tx_hash,
                abi_encoded,
            },
            crate::types::TxAuth::L2 { signed_bytes } => Self::L2 { signed_bytes },
            crate::types::TxAuth::System {
                tx_hash,
                encoded_2718,
            } => Self::System {
                tx_hash,
                encoded_2718,
            },
        }
    }
}

impl From<crate::types::TxInput> for TxInput {
    fn from(value: crate::types::TxInput) -> Self {
        Self {
            chain_id: value.chain_id,
            gas_used_override: value.gas_used_override,
            force_fail: value.force_fail,
            auth: value.auth.into(),
        }
    }
}

impl From<crate::types::L2ToL1LogEntry> for L2ToL1LogEntry {
    fn from(value: crate::types::L2ToL1LogEntry) -> Self {
        Self {
            l2_shard_id: value.l2_shard_id,
            is_service: value.is_service,
            tx_number_in_block: value.tx_number_in_block,
            sender: value.sender,
            key: value.key,
            value: value.value,
        }
    }
}

impl From<crate::types::BlockInput> for BlockInput {
    fn from(value: crate::types::BlockInput) -> Self {
        Self {
            number: value.number,
            timestamp: value.timestamp,
            base_fee: value.base_fee,
            gas_limit: value.gas_limit,
            coinbase: value.coinbase,
            prev_randao: value.prev_randao,
            transactions: value.transactions.into_iter().map(Into::into).collect(),
            account_preimages: value.account_preimages,
            block_hashes: value.block_hashes,
            storage_proofs: value
                .storage_proofs
                .into_iter()
                .map(|(key, proof)| (key, proof.into()))
                .collect(),
            block_header_hash: value.block_header_hash,
            l2_to_l1_logs: value.l2_to_l1_logs.into_iter().map(Into::into).collect(),
            expected_tree_root: value.expected_tree_root,
        }
    }
}

impl TryFrom<crate::types::BatchMeta> for BatchMeta {
    type Error = ConversionError;

    fn try_from(value: crate::types::BatchMeta) -> Result<Self, Self::Error> {
        if value.pubdata_content != crate::types::PUBDATA_CONTENT_FULL {
            return Err(ConversionError::UnsupportedPubdataContent(
                value.pubdata_content,
            ));
        }
        Ok(Self {
            tree_root_before: value.tree_root_before,
            leaf_count_before: value.leaf_count_before,
            block_number_before: value.block_number_before,
            last_block_timestamp_before: value.last_block_timestamp_before,
            block_hashes_blake_before: value.block_hashes_blake_before,
            previous_block_hashes: value.previous_block_hashes,
            upgrade_tx_hash: value.upgrade_tx_hash,
            da_commitment_scheme: value.da_commitment_scheme,
            pubdata: value.pubdata,
            multichain_root: value.multichain_root,
            sl_chain_id: value.sl_chain_id,
            blob_versioned_hashes: value.blob_versioned_hashes,
            tree_update: value.tree_update.map(Into::into),
            account_preimages_after: value.account_preimages_after,
            fri_proof_verification_enabled: value.fri_proof_verification_enabled,
            max_tx_gas_limit: value.max_tx_gas_limit,
            interop_proofs: value.interop_proofs.map(TryInto::try_into).transpose()?,
        })
    }
}

impl TryFrom<crate::types::BatchInput> for BatchInput {
    type Error = ConversionError;

    fn try_from(value: crate::types::BatchInput) -> Result<Self, Self::Error> {
        if value.spec_id > 2 {
            return Err(ConversionError::UnsupportedSpec(value.spec_id));
        }
        Ok(Self {
            version: BATCH_INPUT_VERSION,
            chain_id: value.chain_id,
            spec_id: value.spec_id,
            protocol_version_minor: value.protocol_version_minor,
            blocks: value.blocks.into_iter().map(Into::into).collect(),
            batch_meta: value.batch_meta.try_into()?,
            bytecodes: value.bytecodes,
        })
    }
}
