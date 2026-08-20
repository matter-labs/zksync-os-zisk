//! Build a wire-v2 `BatchInput` from a prover-neutral zksync-os test-rig
//! state dump (JSON), so EVM test-corpus batches can be executed by the
//! ZiSK REVM guest.
//!
//! The dump carries a single block, the full pre/post flat-storage state
//! (leaves + preimages), the signed transactions, and the native STF's
//! reference outputs. This tool reconstructs the witness the guest needs —
//! storage proofs, account preimages, bytecodes, tree update — writes the
//! serialized artifacts, and cross-checks the lib executor against the
//! native reference values.
//!
//! Usage:
//!   cargo run --bin dump_to_batchinput -- <dump.json> <out_dir> [--no-validate]
//!
//! Outputs:
//!   <out_dir>/batch_input.bin — `BatchInput` in the `lib::wire` encoding
//!   <out_dir>/input.bin       — ziskemu framing: [len u64 LE][wire bytes][zero pad to 8]
//!
//! `--no-validate` skips the native-reference comparison — for corpus entries
//! where the guest is expected to panic (the artifacts are always written).
#![cfg_attr(test, allow(dead_code))]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use revm::primitives::{Address, B256, KECCAK_EMPTY, U256};
use zksync_os_revm::ZkSpecId;
use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::hash::keccak256;
use zksync_os_zisk_lib::merkle::{
    blake2s, derive_account_properties_key, derive_flat_storage_key, empty_subtree_hash, hash_leaf,
    AccountProperties, BatchTreeUpdate, NeighborProofEntry, SlotProofEntry, StorageProof, TreeLeaf,
    WriteOp, TREE_DEPTH,
};
use zksync_os_zisk_lib::types::*;
use zksync_os_zisk_lib::wire;

// ---------------------------------------------------------------------------
// Bundle schema (all 32-byte values lowercase hex without 0x)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct DLeaf {
    index: u64,
    key: String,
    value: String,
    next: u64,
}

#[derive(serde::Deserialize)]
struct DPre {
    hash: String,
    bytes: String,
}

#[derive(serde::Deserialize)]
struct DState {
    root: String,
    #[allow(dead_code)]
    next_free_slot: u64,
    #[allow(dead_code)]
    leaf_count: u64,
    leaves: Vec<DLeaf>,
    preimages: Vec<DPre>,
}

#[derive(serde::Deserialize)]
struct DBlock {
    number: u64,
    timestamp: u64,
    base_fee: u64,
    gas_limit: u64,
    coinbase: String,
    prev_randao: String,
    gas_used: u64,
}

#[derive(serde::Deserialize)]
struct DTx {
    signed: String,
    gas_used: u64,
    /// Native tx_result was Err: the STF REJECTED the tx at validation and
    /// rolled back every effect — it is not part of the sealed block (no
    /// state change, no gas, no transactions-rolling-hash contribution).
    #[serde(default)]
    failed: bool,
}

#[derive(serde::Deserialize)]
struct DDump {
    chain_id: u64,
    spec_id: u8,
    protocol_version_minor: u32,
    da_commitment_scheme: u8,
    block: DBlock,
    tree_root_before: String,
    leaf_count_before: u64,
    tree_root_after: String,
    leaf_count_after: u64,
    pre: DState,
    post: DState,
    txs: Vec<DTx>,
    pubdata: String,
    block_header_hash: String,
    block_hashes_blake_before: String,
    previous_block_hashes: Vec<String>,
    native_state_before: String,
    native_state_after: String,
    native_chain_config_hash: String,
    native_batch_output_hash: String,
    native_batch_public_input: String,
    #[serde(default)]
    chain_config_fri: bool,
    /// 0 when the bundle carries no chain config. `resolve_max_tx_gas_limit`
    /// substitutes the witness value; the native-reference comparison uses
    /// this field verbatim.
    #[serde(default)]
    chain_config_max_tx_gas_limit: u64,
    /// Chain-config pubdata content: 0 = FullPubdata, 1 = LogsOnly. The native
    /// state-dump hook does not export the field, so a bundle without it is a
    /// full-pubdata chain, which is the only mode the dump rig configures.
    #[serde(default)]
    chain_config_pubdata_content: u8,
    /// Pre-block chain position (hook commit a37838a8): both feed the
    /// pre-block ChainStateCommitment. Old bundles (chain-start blocks)
    /// lack them: block_number_before falls back to block.number - 1 and
    /// the timestamp to 0.
    #[serde(default)]
    block_number_before: Option<u64>,
    #[serde(default)]
    last_block_timestamp_before: u64,
    /// Pre-block ring head `block_hashes_before[0]` = hash of block
    /// `number - 256` (zero for number <= 256). Needed to serve BLOCKHASH at
    /// full 256 depth: `previous_block_hashes` carries only ring[1..256]
    /// (blocks number-255..number-1), and from block 257 on the evicted head
    /// is a real hash that is NOT derivable host-side (the bundle holds only
    /// its blake commitment inside block_hashes_blake_before).
    #[serde(default)]
    block_hash_ring_head: String,
}

/// Per-tx gas cap for the witness when the bundle carries no chain config.
///
/// The guest bounds every L2 transaction by `min(block_gas_limit,
/// max_tx_gas_limit)`. Any substitute below the block gas limit would reject
/// transactions the native rig executed, so the substitute must be
/// non-binding: the bound then reduces to the block gas limit, which native
/// enforces too.
const UNCONFIGURED_MAX_TX_GAS_LIMIT: u64 = u64::MAX;

/// Resolve the per-tx gas cap the witness commits to. A v0.3.0-line bundle
/// reports 0 (that forward path has no ChainConfig).
fn resolve_max_tx_gas_limit(bundle_value: u64) -> u64 {
    if bundle_value == 0 {
        UNCONFIGURED_MAX_TX_GAS_LIMIT
    } else {
        bundle_value
    }
}

fn hbytes(s: &str) -> Vec<u8> {
    alloy_primitives::hex::decode(s).expect("hex")
}
fn hb256(s: &str) -> B256 {
    B256::from_slice(&hbytes(s))
}
fn haddr(s: &str) -> Address {
    Address::from_slice(&hbytes(s))
}

fn zk_spec(spec_id: u8) -> ZkSpecId {
    match spec_id {
        0 => ZkSpecId::AtlasV1,
        1 => ZkSpecId::AtlasV2,
        2 => ZkSpecId::AtlasV3,
        3 => ZkSpecId::AtlasV4,
        x => panic!("unknown spec_id {x}"),
    }
}

// ---------------------------------------------------------------------------
// Dense binary tree over index-ordered leaf hashes
// ---------------------------------------------------------------------------

fn node_hash(l: &B256, r: &B256) -> B256 {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(l.as_slice());
    b[32..].copy_from_slice(r.as_slice());
    blake2s(&b)
}

/// All populated levels (levels[0] = leaves, top level has len 1).
fn build_levels(leaf_hashes: Vec<B256>) -> Vec<Vec<B256>> {
    let mut levels = vec![leaf_hashes];
    while levels.last().unwrap().len() > 1 {
        let d = levels.len() - 1;
        let cur = levels.last().unwrap();
        let mut next = Vec::with_capacity(cur.len().div_ceil(2));
        let mut j = 0;
        while j < cur.len() {
            let l = cur[j];
            let r = if j + 1 < cur.len() {
                cur[j + 1]
            } else {
                empty_subtree_hash(d as u8)
            };
            next.push(node_hash(&l, &r));
            j += 2;
        }
        levels.push(next);
    }
    levels
}

fn dense_root(levels: &[Vec<B256>]) -> B256 {
    let mut node = levels.last().unwrap()[0];
    for d in (levels.len() - 1)..(TREE_DEPTH as usize) {
        node = node_hash(&node, &empty_subtree_hash(d as u8));
    }
    node
}

fn siblings_for(levels: &[Vec<B256>], i: u64) -> Vec<B256> {
    let mut sib = Vec::with_capacity(TREE_DEPTH as usize);
    for d in 0..(TREE_DEPTH as usize) {
        let pos = ((i >> d) ^ 1) as usize;
        let s = if d < levels.len() {
            levels[d]
                .get(pos)
                .copied()
                .unwrap_or(empty_subtree_hash(d as u8))
        } else {
            empty_subtree_hash(d as u8)
        };
        sib.push(s);
    }
    sib
}

// ---------------------------------------------------------------------------
// Tracking pass: a recording DatabaseRef backed by the full pre-state,
// used to discover exactly which slots/accounts the guest's REVM will read.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RecErr(String);
impl core::fmt::Display for RecErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for RecErr {}
impl revm::database_interface::DBErrorMarker for RecErr {}

struct RecordingDb {
    storage: HashMap<B256, B256>,      // flat_key -> value
    preimages: HashMap<B256, Vec<u8>>, // blake2s hash -> preimage bytes
    code: HashMap<B256, Vec<u8>>,      // keccak256(code) -> code
    block_hashes: HashMap<u64, B256>,
    read_slots: RefCell<BTreeSet<B256>>,
    read_accounts: RefCell<BTreeSet<Address>>,
}

impl RecordingDb {
    /// Read an account's pre-state properties and record the two reads the
    /// guest's `ProvenDB::basic_ref` authenticates: the account itself and its
    /// account-properties flat key, whose proof carries the account's existence.
    fn read_account_props(&self, address: Address) -> Result<Option<AccountProperties>, RecErr> {
        self.read_accounts.borrow_mut().insert(address);
        let fk = derive_account_properties_key(&address.into_array());
        self.read_slots.borrow_mut().insert(fk);
        match self.storage.get(&fk) {
            Some(hash) if !hash.is_zero() => {
                let preimage = self.preimages.get(hash).ok_or_else(|| {
                    RecErr(format!(
                        "no preimage for account {address} props hash {hash}"
                    ))
                })?;
                AccountProperties::decode(preimage)
                    .map(Some)
                    .map_err(|e| RecErr(format!("account {address} props blob: {e}")))
            }
            _ => Ok(None),
        }
    }
}

impl revm::DatabaseRef for RecordingDb {
    type Error = RecErr;

    fn basic_ref(&self, address: Address) -> Result<Option<revm::state::AccountInfo>, RecErr> {
        let Some(props) = self.read_account_props(address)? else {
            return Ok(None);
        };
        let code_hash = if props.observable_bytecode_hash.is_zero() {
            if props.nonce == 0 && props.balance == [0u8; 32] {
                B256::ZERO
            } else {
                KECCAK_EMPTY
            }
        } else {
            props.observable_bytecode_hash
        };
        let code = self
            .code
            .get(&code_hash)
            .map(|c| revm::state::Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(c)));
        Ok(Some(revm::state::AccountInfo {
            nonce: props.nonce,
            balance: U256::from_be_bytes(props.balance),
            code_hash,
            code,
            account_id: None,
        }))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<revm::state::Bytecode, RecErr> {
        if code_hash.is_zero() || code_hash == KECCAK_EMPTY {
            return Ok(revm::state::Bytecode::default());
        }
        self.code
            .get(&code_hash)
            .map(|c| revm::state::Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(c)))
            .ok_or_else(|| {
                RecErr(format!(
                    "no bytecode for code_hash {code_hash} in dump preimages"
                ))
            })
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, RecErr> {
        let slot = B256::from(index.to_be_bytes::<32>());
        let fk = derive_flat_storage_key(&address.into_array(), &slot);
        self.read_slots.borrow_mut().insert(fk);
        Ok(self
            .storage
            .get(&fk)
            .map(|v| U256::from_be_bytes(v.0))
            .unwrap_or_default())
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, RecErr> {
        Ok(self.block_hashes.get(&number).copied().unwrap_or_default())
    }
}

/// The EIP-2935 history contract and the size of its ring, as
/// `executor::eip2935` states them.
const HISTORY_STORAGE_ADDRESS: Address =
    revm::primitives::address!("0000f90827f1c53a10cb7a02335b175320002935");
const HISTORY_SERVE_WINDOW: u64 = 8191;

/// Mirror of executor::eip2935::apply_pre_block_write for the tracking pass.
///
/// The step runs before the block's first transaction, so a run of the
/// transactions alone observes neither of its two reads, and the witness comes
/// out without the history contract's account-properties proof and without the
/// ring slot's proof — both of which the guest requires. Performing the write
/// here also puts its value in the overlay, so a transaction that reads the ring
/// slot observes what the guest observes.
fn tracking_pre_block_write(
    block_number: u64,
    cache_db: &mut revm::database::CacheDB<RecordingDb>,
) {
    use revm::DatabaseRef;

    let props = cache_db
        .db
        .read_account_props(HISTORY_STORAGE_ADDRESS)
        .expect("history contract pre-state");
    // Native's gate is `is_contract()`: the account holds code and carries no
    // EIP-7702 delegation.
    let is_contract = props.is_some_and(|p| {
        p.observable_bytecode_len > 0
            && (p.versioning >> 56) as u8
                != zksync_os_zisk_lib::account_props::DELEGATED_STATUS_BYTE
    });
    if !is_contract {
        return;
    }

    let slot = U256::from((block_number - 1) % HISTORY_SERVE_WINDOW);
    cache_db
        .storage_ref(HISTORY_STORAGE_ADDRESS, slot)
        .expect("history contract ring slot");
    let parent_hash = cache_db
        .db
        .block_hash_ref(block_number - 1)
        .expect("RecordingDb::block_hash_ref is infallible");
    cache_db
        .insert_account_storage(
            HISTORY_STORAGE_ADDRESS,
            slot,
            U256::from_be_bytes(parent_hash.0),
        )
        .expect("history contract pre-state");
}

/// Mirror of executor::evm::run_evm_block for the tracking pass (records
/// reads). Transactions are built by the guest's own
/// `executor::tx::build_proven_tx`, so tracking and guest execution can
/// never diverge on tx construction.
fn tracking_run(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    cache_db: &mut revm::database::CacheDB<RecordingDb>,
    max_tx_gas_limit: Option<u64>,
) {
    use revm::ExecuteCommitEvm;
    use zksync_os_revm::{zk_context, ZkBuilder};

    if ZkSpecId::AtlasV4.is_enabled_in(spec_id) {
        tracking_pre_block_write(block.number, cache_db);
    }

    let mut evm = zk_context(cache_db, spec_id)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.spec = spec_id;
        })
        .modify_block_chained(|blk| {
            blk.number = U256::from(block.number);
            blk.timestamp = U256::from(block.timestamp);
            blk.beneficiary = block.coinbase;
            blk.basefee = block.base_fee;
            blk.gas_limit = block.gas_limit;
            blk.prevrandao = Some(block.prev_randao);
        })
        .build_zk()
        .with_precompiles(executor::system_hooks::ZKsyncOsPrecompiles::new_with_spec(spec_id));

    for (tx_idx, tx_input) in block.transactions.iter().enumerate() {
        evm.0.ctx.journaled_state.set_tx_number(tx_idx as u16);
        let (tx, _tx_hash, _tx_type) =
            executor::tx::build_proven_tx(tx_input, block.gas_limit, max_tx_gas_limit);
        match evm.transact_commit(tx) {
            Ok(_result) => {
                let _ = evm.0.ctx.journaled_state.take_l2_to_l1_logs();
            }
            Err(e) => panic!("tracking tx {tx_idx} failed: {e:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Witness construction
// ---------------------------------------------------------------------------

/// Recover keccak-keyed deployed code from the dump's blake2s-keyed preimage
/// store: each 124-byte account blob names its code blob (code ‖ pad ‖
/// artifacts, stored under blake2s `bytecode_hash`); the raw code is its
/// `unpadded_code_len` prefix, cross-checked against keccak256 ==
/// `observable_bytecode_hash`.
fn derive_codes(preimages: &HashMap<B256, Vec<u8>>) -> BTreeMap<B256, Vec<u8>> {
    let mut codes = BTreeMap::new();
    for blob in preimages.values() {
        // The preimage store mixes account blobs with code blobs; only the
        // ones that decode as account properties name a bytecode.
        let Ok(props) = AccountProperties::decode(blob) else {
            continue;
        };
        let obs = props.observable_bytecode_hash;
        if obs.is_zero() || obs == KECCAK_EMPTY || codes.contains_key(&obs) {
            continue;
        }
        let Some(code_blob) = preimages.get(&props.bytecode_hash) else {
            continue;
        };
        let len = props.unpadded_code_len as usize;
        if code_blob.len() < len {
            continue;
        }
        let code = &code_blob[..len];
        if keccak256(code) != obs {
            continue; // not an account-properties blob after all
        }
        codes.insert(obs, code.to_vec());
    }
    codes
}

fn build_storage_proofs(
    read_slots: &BTreeSet<B256>,
    pre_by_index: &[(u64, B256, B256, u64)],
    levels: &[Vec<B256>],
) -> Vec<(B256, StorageProof)> {
    let key_to_leaf: HashMap<B256, (u64, B256, u64)> = pre_by_index
        .iter()
        .map(|(idx, k, v, n)| (*k, (*idx, *v, *n)))
        .collect();
    let mut by_key: Vec<&(u64, B256, B256, u64)> = pre_by_index.iter().collect();
    by_key.sort_by_key(|entry| entry.1);

    let entry_for = |idx: u64, val: B256, next: u64| SlotProofEntry {
        index: idx,
        value: val,
        next_index: next,
        siblings: siblings_for(levels, idx),
    };

    let mut proofs = Vec::with_capacity(read_slots.len());
    for fk in read_slots {
        if let Some((idx, val, next)) = key_to_leaf.get(fk) {
            proofs.push((*fk, StorageProof::Existing(entry_for(*idx, *val, *next))));
        } else {
            // Non-existence: bracket fk between the linked-list predecessor
            // (greatest key < fk, guaranteed by the MIN guard) and its successor.
            let pos = by_key.partition_point(|e| e.1 < *fk);
            assert!(pos > 0, "no predecessor leaf for non-existing key {fk}");
            let l = by_key[pos - 1];
            let r = &pre_by_index[l.3 as usize];
            assert!(r.1 > *fk, "pre-state linked list inconsistent around {fk}");
            proofs.push((
                *fk,
                StorageProof::NonExisting {
                    left_neighbor: NeighborProofEntry {
                        entry: entry_for(l.0, l.2, l.3),
                        leaf_key: l.1,
                    },
                    right_neighbor: NeighborProofEntry {
                        entry: entry_for(r.0, r.2, r.3),
                        leaf_key: r.1,
                    },
                },
            ));
        }
    }
    proofs
}

/// SystemContext system contract, address `0x800b`. Slot 0 holds the
/// settlement-layer chain id.
const SYSTEM_CONTEXT_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x0b,
];
/// MessageRoot aggregator system contract, address `0x10005`.
const MESSAGE_ROOT_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x05,
];
/// L2InteropCommitmentTree system contract, address `0x10012`. Slot 0 holds the
/// tree height, and `_nodes` lives at contract slot 2.
const INTEROP_COMMITMENT_TREE_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x12,
];

/// Storage slot of `_nodes[height][0]` for a `FullMerkle` engine whose `_nodes`
/// dynamic array lives at `nodes_base_slot`. This mirrors lib
/// `executor::interop::nodes_root_slot`: solidity addresses `_nodes[height][0]`
/// as `keccak256(keccak256(nodes_base_slot) + height)`.
fn nodes_root_slot(nodes_base_slot: u8, height: &B256) -> B256 {
    let base = U256::from_be_bytes(keccak256(B256::with_last_byte(nodes_base_slot).as_slice()).0);
    let slot = base.wrapping_add(U256::from_be_bytes(height.0));
    keccak256(&slot.to_be_bytes::<32>())
}

/// A flat-storage tree the interop slot proofs are built against, as the
/// `(index, key, value, next)` leaf records plus the dense level hashes.
struct ProvableTree<'a> {
    by_index: &'a [(u64, B256, B256, u64)],
    levels: &'a [Vec<B256>],
}

impl ProvableTree<'_> {
    /// Prove `fk` against this tree: `Existing` with the stored value when the
    /// leaf is present, `NonExisting` bracketed by its linked-list neighbours
    /// otherwise.
    fn prove(&self, fk: &B256) -> StorageProof {
        let entry_for = |idx: u64, val: B256, next: u64| SlotProofEntry {
            index: idx,
            value: val,
            next_index: next,
            siblings: siblings_for(self.levels, idx),
        };
        if let Some((idx, _, val, next)) = self.by_index.iter().find(|(_, k, _, _)| k == fk) {
            return StorageProof::Existing(entry_for(*idx, *val, *next));
        }
        // Non-existence: bracket fk between its linked-list predecessor
        // (greatest key < fk, guaranteed by the MIN guard) and successor.
        let l = self
            .by_index
            .iter()
            .filter(|e| e.1 < *fk)
            .max_by_key(|e| e.1)
            .unwrap_or_else(|| panic!("no predecessor leaf for interop key {fk}"));
        let r = &self.by_index[l.3 as usize];
        assert!(r.1 > *fk, "tree linked list inconsistent around {fk}");
        StorageProof::NonExisting {
            left_neighbor: NeighborProofEntry {
                entry: entry_for(l.0, l.2, l.3),
                leaf_key: l.1,
            },
            right_neighbor: NeighborProofEntry {
                entry: entry_for(r.0, r.2, r.3),
                leaf_key: r.1,
            },
        }
    }

    /// The value stored at `fk`, or zero when the leaf is absent.
    fn value_at(&self, fk: &B256) -> B256 {
        self.by_index
            .iter()
            .find(|(_, k, _, _)| k == fk)
            .map(|(_, _, v, _)| *v)
            .unwrap_or(B256::ZERO)
    }

    /// The two proofs of a `FullMerkle` engine's root: the height slot, then the
    /// `_nodes[height][0]` slot the height selects.
    fn prove_merkle_engine_root(
        &self,
        address: &[u8; 20],
        height_slot: B256,
        nodes_base_slot: u8,
    ) -> (StorageProof, StorageProof) {
        let height_key = derive_flat_storage_key(address, &height_slot);
        let height = self.value_at(&height_key);
        let root_key = derive_flat_storage_key(address, &nodes_root_slot(nodes_base_slot, &height));
        (self.prove(&height_key), self.prove(&root_key))
    }
}

/// Build the interop slot proofs the guest authenticates (`executor::interop`).
///
/// Native reads `sl_chain_id` (SystemContext `0x800b` slot 0) and the multichain
/// root (MessageRoot `0x10005`) at the POST-batch tree, so those proofs are
/// built against the post-state tree. The interop commitment tree (`0x10012`)
/// root is read once before the batch's first block and once after its last, so
/// its proofs are built against the pre-state tree and the post-state tree
/// respectively.
///
/// An absent slot yields a NonExisting proof, so a chain that is not a
/// settlement layer and carries no commitment tree (the EVM test-corpus case)
/// derives `sl_chain_id` 0, `multichain_root` 0 and both commitment tree roots
/// 0. A present slot yields an Existing proof with the stored value, so a real
/// settlement layer derives the true values too. This matches what native
/// reads, so the derived scalars agree with the recorded batch-output hash.
fn build_interop_proofs(
    pre: &ProvableTree,
    post: &ProvableTree,
    commits_interop_commitment_tree: bool,
) -> InteropSlotProofs {
    const MULTICHAIN_HEIGHT_SLOT: B256 = B256::with_last_byte(0x04);
    const MULTICHAIN_NODES_SLOT: u8 = 0x06;
    const COMMITMENT_TREE_HEIGHT_SLOT: B256 = B256::ZERO;
    const COMMITMENT_TREE_NODES_SLOT: u8 = 0x02;

    let sl_key = derive_flat_storage_key(&SYSTEM_CONTEXT_ADDRESS, &B256::ZERO);
    let (multichain_height, multichain_root) = post.prove_merkle_engine_root(
        &MESSAGE_ROOT_ADDRESS,
        MULTICHAIN_HEIGHT_SLOT,
        MULTICHAIN_NODES_SLOT,
    );

    let commitment_tree = commits_interop_commitment_tree.then(|| {
        let (height_begin, root_begin) = pre.prove_merkle_engine_root(
            &INTEROP_COMMITMENT_TREE_ADDRESS,
            COMMITMENT_TREE_HEIGHT_SLOT,
            COMMITMENT_TREE_NODES_SLOT,
        );
        let (height_end, root_end) = post.prove_merkle_engine_root(
            &INTEROP_COMMITMENT_TREE_ADDRESS,
            COMMITMENT_TREE_HEIGHT_SLOT,
            COMMITMENT_TREE_NODES_SLOT,
        );
        InteropCommitmentTreeProofs {
            height_begin,
            root_begin,
            height_end,
            root_end,
        }
    });

    InteropSlotProofs {
        sl_chain_id: post.prove(&sl_key),
        multichain_height,
        multichain_root,
        commitment_tree,
    }
}

fn build_batch_input(d: &DDump, no_header_check: bool) -> BatchInput {
    assert!(d.block.number >= 1, "block number must be >= 1");
    let spec = zk_spec(d.spec_id);
    if d.da_commitment_scheme == 4 {
        eprintln!("WARNING: DA scheme 4 (blobs) needs versioned hashes the bundle does not carry");
    }

    // Full pre-state maps.
    let mut storage: HashMap<B256, B256> = HashMap::new();
    for l in &d.pre.leaves {
        storage.insert(hb256(&l.key), hb256(&l.value));
    }
    let mut preimages: HashMap<B256, Vec<u8>> = HashMap::new();
    for p in d.pre.preimages.iter().chain(d.post.preimages.iter()) {
        let h = hb256(&p.hash);
        let b = hbytes(&p.bytes);
        assert_eq!(
            blake2s(&b),
            h,
            "preimage bytes do not hash to their key {h}"
        );
        preimages.insert(h, b);
    }
    let codes = derive_codes(&preimages);

    // Pre leaves by index; the native tree is dense from 0.
    let mut pre_by_index: Vec<(u64, B256, B256, u64)> = d
        .pre
        .leaves
        .iter()
        .map(|l| (l.index, hb256(&l.key), hb256(&l.value), l.next))
        .collect();
    pre_by_index.sort_by_key(|e| e.0);
    assert_eq!(
        pre_by_index.len() as u64,
        d.leaf_count_before,
        "dense leaf count"
    );
    for (i, e) in pre_by_index.iter().enumerate() {
        assert_eq!(e.0, i as u64, "pre-state tree must be dense from index 0");
    }

    let leaf_hashes: Vec<B256> = pre_by_index
        .iter()
        .map(|(_, k, v, n)| hash_leaf(k, v, *n))
        .collect();
    let levels = build_levels(leaf_hashes);
    let root_before = hb256(&d.tree_root_before);
    assert_eq!(
        hb256(&d.pre.root),
        root_before,
        "pre.root != tree_root_before"
    );
    assert_eq!(
        dense_root(&levels),
        root_before,
        "dense pre-state root != tree_root_before"
    );

    // BLOCKHASH ring: previous_block_hashes[j] = hash of block (N - len + j).
    let ring: Vec<B256> = d.previous_block_hashes.iter().map(|s| hb256(s)).collect();
    let mut block_hashes: Vec<(u64, B256)> = Vec::new();
    for (j, h) in ring.iter().enumerate() {
        let offset = (ring.len() - j) as u64;
        if !h.is_zero() && d.block.number >= offset {
            block_hashes.push((d.block.number - offset, *h));
        }
    }
    // Ring head: hash of block N-256, evicted from previous_block_hashes but
    // still BLOCKHASH-visible (the opcode's window is the last 256 blocks).
    if !d.block_hash_ring_head.is_empty() {
        let h = hb256(&d.block_hash_ring_head);
        if !h.is_zero() && d.block.number >= 256 {
            block_hashes.push((d.block.number - 256, h));
        }
    }

    let native_gas: u64 = d.txs.iter().map(|t| t.gas_used).sum();
    if native_gas != d.block.gas_used {
        eprintln!(
            "WARNING: sum of tx gas_used ({native_gas}) != block gas_used ({}); \
             the armed header-hash check will fail",
            d.block.gas_used
        );
    }

    let block_env = BlockInput {
        number: d.block.number,
        timestamp: d.block.timestamp,
        base_fee: d.block.base_fee,
        gas_limit: d.block.gas_limit,
        coinbase: haddr(&d.block.coinbase),
        prev_randao: hb256(&d.block.prev_randao),
        transactions: d
            .txs
            .iter()
            // Natively rejected txs are EXCLUDED from the block by the STF
            // (zk tx_loop validation-error branch: full rollback; the tx hash
            // is folded into the rolling hash only for Ok results). Omission
            // — not force_fail — is the faithful mapping: force_fail keeps
            // the tx in the block (nonce bump, rolling-hash entry, L2 tx
            // count) and REVM validation still rejects intrinsic-gas cases
            // before the force_fail short-circuit.
            .filter(|t| !t.failed)
            .map(|t| TxInput {
                chain_id: Some(d.chain_id),
                gas_used_override: Some(t.gas_used),
                force_fail: false,
                auth: TxAuth::L2 {
                    signed_bytes: hbytes(&t.signed),
                },
            })
            .collect(),
        account_preimages: vec![],
        block_hashes,
        storage_proofs: vec![],
        // Arm the guest's canonical header-hash assertion with the native
        // value; a zero hash makes the guest skip the check (used while the
        // native-vs-guest header derivation is not yet reconciled, so
        // panics reflect mid-execution failures only).
        block_header_hash: if no_header_check {
            B256::ZERO
        } else {
            hb256(&d.block_header_hash)
        },
        l2_to_l1_logs: vec![],
        expected_tree_root: B256::ZERO,
    };

    // ---- tracking pass: discover the read set (same REVM as the guest) ----
    let rec = RecordingDb {
        storage: storage.clone(),
        preimages: preimages.clone(),
        code: codes.iter().map(|(k, v)| (*k, v.clone())).collect(),
        block_hashes: block_env.block_hashes.iter().copied().collect(),
        read_slots: RefCell::new(BTreeSet::new()),
        read_accounts: RefCell::new(BTreeSet::new()),
    };
    let mut cache = revm::database::CacheDB::new(rec);
    // Resolve the per-tx gas cap the same way `build_batch_input` does below.
    // Only a spec that applies EIP-7825 passes it to the transaction builder.
    let max_tx_gas_limit = ZkSpecId::AtlasV4
        .is_enabled_in(spec)
        .then(|| resolve_max_tx_gas_limit(d.chain_config_max_tx_gas_limit));
    let tracked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tracking_run(d.chain_id, spec, &block_env, &mut cache, max_tx_gas_limit);
    }));
    if tracked.is_err() {
        eprintln!(
            "WARNING: tracking pass panicked — the witness covers reads up to \
             the panic point only (the guest is expected to panic there too)"
        );
    }
    let read_slots = cache.db.read_slots.borrow().clone();
    let read_accounts = cache.db.read_accounts.borrow().clone();
    println!(
        "tracking: {} slot reads, {} account reads, {} bytecodes",
        read_slots.len(),
        read_accounts.len(),
        codes.len()
    );

    let storage_proofs = build_storage_proofs(&read_slots, &pre_by_index, &levels);

    // Pre-state account preimages for every existing account REVM read.
    let key_to_leaf: HashMap<B256, (u64, B256, u64)> = pre_by_index
        .iter()
        .map(|(idx, k, v, n)| (*k, (*idx, *v, *n)))
        .collect();
    let mut account_preimages: Vec<(Address, Vec<u8>)> = Vec::new();
    for addr in &read_accounts {
        let fk = derive_account_properties_key(&addr.into_array());
        if let Some((_, val, _)) = key_to_leaf.get(&fk) {
            if !val.is_zero() {
                let pre = preimages.get(val).expect("pre account preimage");
                account_preimages.push((*addr, pre.clone()));
            }
        }
    }

    // ---- tree_update from the pre/post diff ----
    let pre_val_by_key: HashMap<B256, B256> =
        pre_by_index.iter().map(|(_, k, v, _)| (*k, *v)).collect();
    let post_by_key: HashMap<B256, (u64, B256, u64)> = d
        .post
        .leaves
        .iter()
        .map(|l| (hb256(&l.key), (l.index, hb256(&l.value), l.next)))
        .collect();

    let mut updates: Vec<(u64, B256, B256)> = Vec::new(); // (pre index, key, post value)
    let mut inserts: Vec<(u64, B256, B256)> = Vec::new(); // (post index, key, value)
    let mut changed_keys: HashSet<B256> = HashSet::new();
    for (k, (post_idx, post_val, _)) in &post_by_key {
        match pre_val_by_key.get(k) {
            Some(prev) if prev != post_val => {
                updates.push((key_to_leaf[k].0, *k, *post_val));
                changed_keys.insert(*k);
            }
            Some(_) => {}
            None => {
                inserts.push((*post_idx, *k, *post_val));
                changed_keys.insert(*k);
            }
        }
    }
    updates.sort_by_key(|e| e.0);
    // Inserts must be applied in post-index order: the guest assigns dense
    // indices from leaf_count_before, which must reproduce the post indices.
    inserts.sort_by_key(|e| e.0);

    let mut operations: Vec<WriteOp> = Vec::new();
    let mut entries: Vec<(B256, B256)> = Vec::new();
    for (idx, k, v) in &updates {
        operations.push(WriteOp::Update { index: *idx });
        entries.push((*k, *v));
    }
    // Insert predecessors must reflect the list AT INSERT TIME, not the final
    // post-state: a later insert can land between a leaf and its predecessor,
    // so the post-state `next` pointers are not usable. Simulate the evolving
    // linked list instead (mirrors the server's build_tree_update).
    let mut list_key_to_index: BTreeMap<B256, u64> = pre_by_index
        .iter()
        .map(|(idx, k, _, _)| (*k, *idx))
        .collect();
    for (i, (post_idx, k, v)) in inserts.iter().enumerate() {
        assert_eq!(
            *post_idx,
            d.leaf_count_before + i as u64,
            "inserts not dense"
        );
        let prev_index = *list_key_to_index
            .range(..*k)
            .next_back()
            .unwrap_or_else(|| panic!("no predecessor for insert key {k} (MIN guard missing?)"))
            .1;
        operations.push(WriteOp::Insert { prev_index });
        entries.push((*k, *v));
        list_key_to_index.insert(*k, *post_idx);
    }
    println!(
        "tree_update: {} updates, {} inserts",
        updates.len(),
        inserts.len()
    );

    // The dump carries the entire pre-state, so every leaf goes into the
    // witness. Pass 1 of the trust-free tree update then authenticates the
    // whole tree, and pass 2 never meets an unauthenticated sibling — no
    // dedicated anchor leaves (or intermediate hashes) are needed.
    let sorted_leaves: Vec<(u64, TreeLeaf)> = pre_by_index
        .iter()
        .map(|(idx, k, v, n)| {
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
    let tree_update = BatchTreeUpdate {
        operations,
        entries,
        sorted_leaves,
        intermediate_hashes: vec![],
        leaf_count_before: d.leaf_count_before,
    };

    // After-state preimages for accounts whose 0x8003 leaf changed.
    let mut account_preimages_after: Vec<(Address, Vec<u8>)> = Vec::new();
    for addr in &read_accounts {
        let fk = derive_account_properties_key(&addr.into_array());
        if changed_keys.contains(&fk) {
            let post_val = post_by_key[&fk].1;
            let post_pre = preimages.get(&post_val).expect("post account preimage");
            account_preimages_after.push((*addr, post_pre.clone()));
        }
    }

    // v31 batches carry authenticated interop slot proofs; the guest derives
    // sl_chain_id / multichain_root from them and ignores the witness scalars.
    // v30 carries none (its batch-output layout commits neither scalar). An
    // AtlasV4 batch additionally carries the interop commitment tree proofs at
    // both batch boundaries. The post-state proofs need the post-state tree
    // built from the dump's full post leaves.
    let interop_proofs = if d.protocol_version_minor >= 31 {
        let mut post_by_index: Vec<(u64, B256, B256, u64)> = d
            .post
            .leaves
            .iter()
            .map(|l| (l.index, hb256(&l.key), hb256(&l.value), l.next))
            .collect();
        post_by_index.sort_by_key(|e| e.0);
        assert_eq!(
            post_by_index.len() as u64,
            d.leaf_count_after,
            "dense post leaf count"
        );
        for (i, e) in post_by_index.iter().enumerate() {
            assert_eq!(e.0, i as u64, "post-state tree must be dense from index 0");
        }
        let post_leaf_hashes: Vec<B256> = post_by_index
            .iter()
            .map(|(_, k, v, n)| hash_leaf(k, v, *n))
            .collect();
        let post_levels = build_levels(post_leaf_hashes);
        assert_eq!(
            dense_root(&post_levels),
            hb256(&d.tree_root_after),
            "dense post-state root != tree_root_after"
        );
        Some(build_interop_proofs(
            &ProvableTree {
                by_index: &pre_by_index,
                levels: &levels,
            },
            &ProvableTree {
                by_index: &post_by_index,
                levels: &post_levels,
            },
            ZkSpecId::AtlasV4.is_enabled_in(spec),
        ))
    } else {
        None
    };

    let batch_meta = BatchMeta {
        tree_root_before: root_before,
        leaf_count_before: d.leaf_count_before,
        block_number_before: d.block_number_before.unwrap_or(d.block.number - 1),
        last_block_timestamp_before: d.last_block_timestamp_before,
        // Taken verbatim from the bundle, never recomputed: for blocks >= 257
        // the oldest ring entry is a real hash that is NOT derivable from the
        // 255-entry previous_block_hashes list.
        block_hashes_blake_before: hb256(&d.block_hashes_blake_before),
        previous_block_hashes: ring,
        upgrade_tx_hash: B256::ZERO,
        da_commitment_scheme: d.da_commitment_scheme,
        pubdata: hbytes(&d.pubdata),
        multichain_root: B256::ZERO,
        sl_chain_id: 1,
        blob_versioned_hashes: vec![],
        tree_update: Some(tree_update),
        account_preimages_after,
        fri_proof_verification_enabled: d.chain_config_fri,
        max_tx_gas_limit: resolve_max_tx_gas_limit(d.chain_config_max_tx_gas_limit),
        pubdata_content: d.chain_config_pubdata_content,
        interop_proofs,
    };

    BatchInput {
        version: BATCH_INPUT_VERSION,
        chain_id: d.chain_id,
        spec_id: d.spec_id,
        protocol_version_minor: d.protocol_version_minor,
        blocks: vec![BlockInput {
            account_preimages,
            storage_proofs,
            ..block_env
        }],
        batch_meta,
        bytecodes: codes.into_iter().collect(),
    }
}

// ---------------------------------------------------------------------------
// Validation against the native reference values
// ---------------------------------------------------------------------------

fn check(name: &str, computed: &B256, native: &B256) -> bool {
    if computed == native {
        println!("PASS {name}: {computed}");
        true
    } else {
        println!("FAIL {name}: computed {computed} != native {native}");
        false
    }
}

fn validate(d: &DDump, bi: &BatchInput) -> bool {
    let mut ok = true;

    let tu = bi.batch_meta.tree_update.as_ref().unwrap();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tu.apply(&bi.batch_meta.tree_root_before)
    })) {
        Ok((root_after, count_after)) => {
            ok &= check("tree_root_after", &root_after, &hb256(&d.tree_root_after));
            if count_after != d.leaf_count_after {
                println!(
                    "FAIL leaf_count_after: computed {count_after} != native {}",
                    d.leaf_count_after
                );
                ok = false;
            }
        }
        Err(_) => {
            println!("FAIL tree_update.apply panicked");
            ok = false;
        }
    }

    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor::execute_and_commit_debug(bi)
    })) {
        Ok((_out, pi, sb, sa, bh)) => {
            ok &= check("state_before", &sb, &hb256(&d.native_state_before));
            ok &= check("state_after", &sa, &hb256(&d.native_state_after));
            // v0.3.0-line bundles cannot carry these (no native producer in
            // the forward path); state commitments + header hash + pubdata
            // remain the native ground truth there.
            if d.native_batch_output_hash.is_empty() {
                println!(
                    "SKIP batch_output_hash/chain_config_hash/batch_public_input: not in bundle"
                );
                let _ = (pi, bh);
            } else {
                ok &= check(
                    "batch_output_hash",
                    &bh,
                    &hb256(&d.native_batch_output_hash),
                );
                let ccfg = zksync_os_zisk_lib::commitment::chain_config_hash(
                    d.chain_id,
                    d.chain_config_fri,
                    d.chain_config_max_tx_gas_limit,
                    d.chain_config_pubdata_content,
                );
                ok &= check(
                    "chain_config_hash",
                    &ccfg,
                    &hb256(&d.native_chain_config_hash),
                );
                ok &= check(
                    "batch_public_input",
                    &pi,
                    &hb256(&d.native_batch_public_input),
                );
            }
        }
        Err(_) => {
            println!("FAIL executor panicked (see message above)");
            ok = false;
        }
    }
    ok
}

fn frame_for_zisk(wire_bytes: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(8 + wire_bytes.len() + 8);
    framed.extend_from_slice(&(wire_bytes.len() as u64).to_le_bytes());
    framed.extend_from_slice(wire_bytes);
    let pad = (8 - (framed.len() % 8)) % 8;
    framed.extend(std::iter::repeat_n(0u8, pad));
    framed
}

fn main() {
    let mut no_validate = false;
    let mut no_header_check = false;
    let mut pos: Vec<String> = Vec::new();
    for a in std::env::args().skip(1) {
        if a == "--no-validate" {
            no_validate = true;
        } else if a == "--no-header-check" {
            no_header_check = true;
        } else {
            pos.push(a);
        }
    }
    let [dump_path, out_dir]: [String; 2] = pos.try_into().unwrap_or_else(|_| {
        panic!("usage: dump_to_batchinput <dump.json> <out_dir> [--no-validate]")
    });

    let raw =
        std::fs::read_to_string(&dump_path).unwrap_or_else(|e| panic!("read {dump_path}: {e}"));
    let d: DDump = serde_json::from_str(&raw).expect("parse dump json");
    println!(
        "dump: chain_id={} spec_id={} protocol_minor={} block={} txs={} pre_leaves={} post_leaves={}",
        d.chain_id,
        d.spec_id,
        d.protocol_version_minor,
        d.block.number,
        d.txs.len(),
        d.pre.leaves.len(),
        d.post.leaves.len(),
    );

    let bi = build_batch_input(&d, no_header_check);

    let out = Path::new(&out_dir);
    std::fs::create_dir_all(out).expect("create out_dir");
    let data = wire::encode(&bi).expect("wire encode");
    let bin_path = out.join("batch_input.bin");
    std::fs::write(&bin_path, &data).expect("write batch_input.bin");
    let framed = frame_for_zisk(&data);
    let input_path = out.join("input.bin");
    std::fs::write(&input_path, &framed).expect("write input.bin");
    println!(
        "wrote {} ({} bytes) and {} ({} bytes)",
        bin_path.display(),
        data.len(),
        input_path.display(),
        framed.len(),
    );

    if no_validate {
        println!("validation skipped (--no-validate)");
        return;
    }
    if !validate(&d, &bi) {
        std::process::exit(1);
    }
    println!("ALL CHECKS PASSED");
}

// ---------------------------------------------------------------------------
// Unit smoke tests (run via `cargo test`; the example target has test = true)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_bundle_json() -> String {
        let zero = "00".repeat(32);
        let ff = "ff".repeat(32);
        let root = "11".repeat(32);
        let guards = format!(
            r#"[{{"index":0,"key":"{zero}","value":"{zero}","next":1}},
                {{"index":1,"key":"{ff}","value":"{zero}","next":1}}]"#
        );
        format!(
            r#"{{
              "chain_id": 37,
              "spec_id": 2,
              "protocol_version_minor": 31,
              "da_commitment_scheme": 2,
              "block": {{"number":1,"timestamp":42,"base_fee":1000,"gas_limit":100000000,
                         "coinbase":"{cb}","prev_randao":"{zero}","gas_used":0}},
              "tree_root_before": "{root}",
              "leaf_count_before": 2,
              "tree_root_after": "{root}",
              "leaf_count_after": 2,
              "pre": {{"root":"{root}","next_free_slot":2,"leaf_count":2,"leaves":{guards},"preimages":[]}},
              "post": {{"root":"{root}","next_free_slot":2,"leaf_count":2,"leaves":{guards},"preimages":[]}},
              "txs": [{{"signed":"02f870","gas_used":21000}}],
              "pubdata": "",
              "block_header_hash": "{zero}",
              "block_hashes_blake_before": "{zero}",
              "previous_block_hashes": ["{zero}", "{root}"],
              "native_state_before": "{zero}",
              "native_state_after": "{zero}",
              "native_chain_config_hash": "{zero}",
              "native_batch_output_hash": "{zero}",
              "native_batch_public_input": "{zero}"
            }}"#,
            cb = "00".repeat(20),
        )
    }

    #[test]
    fn synthetic_bundle_parses_with_defaults() {
        let d: DDump = serde_json::from_str(&synthetic_bundle_json()).expect("parse");
        assert_eq!(d.chain_id, 37);
        assert_eq!(d.spec_id, 2);
        assert_eq!(d.leaf_count_before, 2);
        assert_eq!(d.pre.leaves.len(), 2);
        assert_eq!(hb256(&d.pre.leaves[1].key), B256::repeat_byte(0xff));
        assert_eq!(d.txs.len(), 1);
        assert_eq!(d.txs[0].gas_used, 21000);
        assert_eq!(hbytes(&d.txs[0].signed), vec![0x02, 0xf8, 0x70]);
        // Chain-config fields default when absent from the bundle. A zero cap
        // means "no chain config"; `resolve_max_tx_gas_limit` maps it to the
        // non-binding witness value.
        assert!(!d.chain_config_fri);
        assert_eq!(d.chain_config_max_tx_gas_limit, 0);
        assert_eq!(
            resolve_max_tx_gas_limit(d.chain_config_max_tx_gas_limit),
            UNCONFIGURED_MAX_TX_GAS_LIMIT
        );
        assert_eq!(d.previous_block_hashes.len(), 2);
        // Mid-chain position fields default for chain-start bundles.
        assert!(d.block_number_before.is_none());
        assert_eq!(d.last_block_timestamp_before, 0);
    }

    /// Full-pipeline plumbing check: a self-consistent empty-block bundle
    /// (reference values computed with the lib's own commitment functions)
    /// must build and pass every validation check.
    #[test]
    fn empty_block_bundle_builds_and_validates() {
        use zksync_os_zisk_lib::{block_header, commitment};

        let hex = |b: &[u8]| alloy_primitives::hex::encode(b);

        // Guard-only tree: MIN(0)->MAX(1), count 2.
        let leaves = [
            (B256::ZERO, B256::ZERO, 1u64),
            (B256::repeat_byte(0xff), B256::ZERO, 1u64),
        ];
        let hashes: Vec<B256> = leaves.iter().map(|(k, v, n)| hash_leaf(k, v, *n)).collect();
        let root = dense_root(&build_levels(hashes));

        // Native reference values for one empty AtlasV3 block (number 1, ts 42).
        let coinbase = [0u8; 20];
        let header_hash = block_header::compute_block_header_hash(
            &B256::ZERO,
            &coinbase,
            &block_header::KECCAK_EMPTY, // AtlasV3 rolling-hash seed, no txs
            &B256::ZERO,
            1,
            100_000_000,
            0,
            42,
            &B256::ZERO,
            1000,
        );
        // The R6-1 block-hash ring authentication rebuilds the pre-state ring
        // from the witness history and checks its Blake2s commitment against
        // block_hashes_blake_before. For this chain-start block the before-ring
        // is all zero (no history), so the pinned value is the Blake2s of a
        // 256-entry zero ring. The after-ring, folded into state_after, is
        // [zero; 255] plus the block-1 header hash (executor
        // reconstruct_block_hashes_blake_after). Both must equal those
        // authenticated reconstructions, not a placeholder zero.
        let bhb_before = commitment::block_hashes_blake(&[B256::ZERO; 255], &B256::ZERO);
        let sb = commitment::state_commitment_hash(&root, 2, 0, &bhb_before, 0);
        let sa = commitment::state_commitment_hash(
            &root,
            2,
            1,
            &commitment::block_hashes_blake(&[B256::ZERO; 255], &header_hash),
            42,
        );
        let l2_logs_root =
            commitment::keccak_two(&commitment::l2_to_l1_logs_root(&[]), &B256::ZERO);
        let bo = commitment::batch_output_hash_native(
            commitment::BatchOutputLayout::V31,
            37,
            42,
            42,
            2,
            &commitment::da_commitment_calldata(&[]),
            0,
            0,
            &commitment::priority_ops_rolling_hash(&[]),
            &l2_logs_root,
            &B256::ZERO,
            &B256::ZERO,
            // Settlement-layer chain id. The guard-only post-state has no
            // SystemContext 0x800b slot, so the v31 guest derives 0 from the
            // NonExisting interop proof. The reference must match the derived
            // value, not the legacy witness scalar.
            0,
        );
        let ccfg = commitment::chain_config_hash(37, false, 1 << 24, 0);
        // A v31 batch commits the three-word public input: released native on
        // that line carries no chain-config word.
        let pi = commitment::batch_public_input_hash(&sb, &sa, None, &bo);

        let zero = "00".repeat(32);
        let guards = format!(
            r#"[{{"index":0,"key":"{zero}","value":"{zero}","next":1}},
                {{"index":1,"key":"{ff}","value":"{zero}","next":1}}]"#,
            ff = "ff".repeat(32),
        );
        let state = format!(
            r#"{{"root":"{r}","next_free_slot":2,"leaf_count":2,"leaves":{guards},"preimages":[]}}"#,
            r = hex(root.as_slice()),
        );
        let json = format!(
            r#"{{
              "chain_id": 37, "spec_id": 2, "protocol_version_minor": 31, "da_commitment_scheme": 2,
              "block": {{"number":1,"timestamp":42,"base_fee":1000,"gas_limit":100000000,
                         "coinbase":"{cb}","prev_randao":"{zero}","gas_used":0}},
              "tree_root_before": "{r}", "leaf_count_before": 2,
              "tree_root_after": "{r}", "leaf_count_after": 2,
              "pre": {state}, "post": {state},
              "txs": [], "pubdata": "",
              "chain_config_max_tx_gas_limit": 16777216,
              "block_header_hash": "{hh}",
              "block_hashes_blake_before": "{bhb}",
              "previous_block_hashes": [],
              "native_state_before": "{sb}",
              "native_state_after": "{sa}",
              "native_chain_config_hash": "{ccfg}",
              "native_batch_output_hash": "{bo}",
              "native_batch_public_input": "{pi}"
            }}"#,
            cb = "00".repeat(20),
            r = hex(root.as_slice()),
            hh = hex(header_hash.as_slice()),
            bhb = hex(bhb_before.as_slice()),
            sb = hex(sb.as_slice()),
            sa = hex(sa.as_slice()),
            ccfg = hex(ccfg.as_slice()),
            bo = hex(bo.as_slice()),
            pi = hex(pi.as_slice()),
        );

        let d: DDump = serde_json::from_str(&json).expect("parse");
        let bi = build_batch_input(&d, false);
        assert_eq!(bi.version, BATCH_INPUT_VERSION);
        assert!(
            validate(&d, &bi),
            "self-consistent bundle must pass all checks"
        );
    }

    /// The dense-tree builders must agree with the lib's proof verifier:
    /// a proof assembled from `siblings_for` recovers `dense_root`.
    #[test]
    fn dense_tree_builders_agree_with_proof_verifier() {
        let data_key = B256::repeat_byte(0x42);
        let data_val = B256::repeat_byte(0x07);
        let leaves = [
            (B256::ZERO, B256::ZERO, 2u64),
            (B256::repeat_byte(0xff), B256::ZERO, 1u64),
            (data_key, data_val, 1u64),
        ];
        let hashes: Vec<B256> = leaves.iter().map(|(k, v, n)| hash_leaf(k, v, *n)).collect();
        let levels = build_levels(hashes);
        let root = dense_root(&levels);
        let proof = SlotProofEntry {
            index: 2,
            value: data_val,
            next_index: 1,
            siblings: siblings_for(&levels, 2),
        };
        assert_eq!(proof.recover_root(&data_key), root);

        // Non-existence bracketing recovers the same root from both neighbors.
        let missing = B256::repeat_byte(0x50);
        let left = SlotProofEntry {
            index: 2,
            value: data_val,
            next_index: 1,
            siblings: siblings_for(&levels, 2),
        };
        let right = SlotProofEntry {
            index: 1,
            value: B256::ZERO,
            next_index: 1,
            siblings: siblings_for(&levels, 1),
        };
        let proof = StorageProof::NonExisting {
            left_neighbor: NeighborProofEntry {
                entry: left,
                leaf_key: data_key,
            },
            right_neighbor: NeighborProofEntry {
                entry: right,
                leaf_key: B256::repeat_byte(0xff),
            },
        };
        let (recovered, value) = proof.verify(&missing).expect("verify");
        assert_eq!(recovered, root);
        assert!(value.is_none());
    }

    /// Every AtlasV4 block authenticates the EIP-2935 history contract before
    /// it runs a transaction, and it does so even where the contract holds no
    /// code — the gate itself reads the account. The tracking pass must
    /// therefore record the account and its account-properties key, which is
    /// the key whose proof carries the account's existence, against a pre-state
    /// that holds no history contract at all.
    #[test]
    fn tracking_records_the_eip2935_history_account_read() {
        let rec = RecordingDb {
            storage: HashMap::new(),
            preimages: HashMap::new(),
            code: HashMap::new(),
            block_hashes: HashMap::new(),
            read_slots: RefCell::new(BTreeSet::new()),
            read_accounts: RefCell::new(BTreeSet::new()),
        };
        let mut cache = revm::database::CacheDB::new(rec);
        tracking_pre_block_write(1, &mut cache);
        assert!(cache
            .db
            .read_accounts
            .borrow()
            .contains(&HISTORY_STORAGE_ADDRESS));
        assert!(cache
            .db
            .read_slots
            .borrow()
            .contains(&derive_account_properties_key(
                &HISTORY_STORAGE_ADDRESS.into_array()
            )));
    }
}
