//! Frozen schema for released `BatchInput` wire version 5.
//!
//! Wire v6 changed `BatchMeta` alone, so this module freezes `BatchInput` and
//! `BatchMeta` and shares every nested type with the current schema. Before a
//! later version changes one of those shared types, freeze a copy of it here,
//! as [`super::v3`] does. Do not change field order or field types.
//! `wire-v5-atlas-v4.hex` pins the encoding.

use revm::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::merkle::BatchTreeUpdate;
use crate::types::{BlockInput, InteropSlotProofs};

/// The released wire version represented by this module.
pub const BATCH_INPUT_VERSION: u32 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct BatchInput {
    pub version: u32,
    pub chain_id: u64,
    pub spec_id: u8,
    pub protocol_version_minor: u32,
    pub blocks: Vec<BlockInput>,
    pub batch_meta: BatchMeta,
    pub bytecodes: Vec<(B256, Vec<u8>)>,
}

#[derive(Serialize, Deserialize, Clone)]
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
    pub pubdata_content: u8,
    pub interop_proofs: Option<InteropSlotProofs>,
}

/// Wire v5 predates the ZKsync OS 0.6.0 chain-config flags, so both normalize
/// to `false`. The executor rejects a v5 input that selects AtlasV5.
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
            tree_update: value.tree_update,
            account_preimages_after: value.account_preimages_after,
            fri_proof_verification_enabled: value.fri_proof_verification_enabled,
            max_tx_gas_limit: value.max_tx_gas_limit,
            pubdata_content: value.pubdata_content,
            l1_tx_filtering_enabled: false,
            large_contracts_enabled: false,
            interop_proofs: value.interop_proofs,
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
            blocks: value.blocks,
            batch_meta: value.batch_meta.into(),
            bytecodes: value.bytecodes,
        }
    }
}
