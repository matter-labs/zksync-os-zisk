//! EVM block execution.
//!
//! Runs a block's transactions through REVM, collects results and L2→L1 logs,
//! and verifies the computed block header hash.

use std::collections::HashSet;

use revm::database::CacheDB;
use revm::primitives::{B256, U256};
use revm::{DatabaseRef, ExecuteCommitEvm, ExecuteEvm};
use revm::primitives::Address;
use zksync_os_revm::{DefaultZk, ZkBuilder, ZkContext, ZkSpecId};

use crate::block_header;
use crate::types::*;
use super::proven_db::ProvenDB;
use super::tx::build_proven_tx;

/// The state effects of one block that batch-level write-map verification needs.
pub(super) struct BlockStateEffects {
    /// Net per-slot storage changes: (address, slot) → the last value written.
    pub(super) storage_writes: Vec<((Address, U256), U256)>,
    /// Accounts that destruction removed from the state.
    pub(super) destroyed_accounts: HashSet<Address>,
    /// Accounts a deployment completed at. Native runs `deploy_code` for every
    /// completed deployment, so these accounts carry the deployed code
    /// encoding even when the deployed runtime code is empty.
    pub(super) deployed_accounts: HashSet<Address>,
}

/// Execute a single block using the shared batch-level CacheDB.
/// Writes from this block remain in the CacheDB for subsequent blocks.
pub(super) fn execute_block_proven(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    cache_db: &mut CacheDB<ProvenDB>,
    max_tx_gas_limit: u64,
) -> (BlockResult, BlockStateEffects) {
    let (tx_results, tx_hashes, computed_l2_to_l1_logs, state_effects) =
        run_evm_block(chain_id, spec_id, block, cache_db, max_tx_gas_limit);

    let total_gas_used: u64 = tx_results.iter().map(|t| t.gas_used).sum();
    // Native commits transactions as a keccak rolling hash over the tx hashes
    // and keeps receipts_root zero in the header. The seed changed with the
    // zksync-os v0.3.x line: zero before AtlasV3, keccak256([]) from AtlasV3.
    let rolling_hash_seed = if ZkSpecId::AtlasV3.is_enabled_in(spec_id) {
        block_header::KECCAK_EMPTY
    } else {
        B256::ZERO
    };
    let tx_root = block_header::transactions_rolling_hash(&tx_hashes, rolling_hash_seed);
    let receipts_root = B256::ZERO;


    // Parent hash = the previous block's hash, taken from the AUTHENTICATED
    // block-hash map, never from the unauthenticated witness `block.block_hashes`.
    //
    // SOUNDNESS: the ring that `block_hashes_blake_before` authenticates
    // is built last-write-wins (`reconstruct_ring`), but a raw `.find()` over
    // `block.block_hashes` is first-match — so a duplicate
    // `(F-1, FORGED) … (F-1, TRUE)` would pass the ring commitment (last = TRUE)
    // yet feed FORGED into the header hash. The map served by
    // `ProvenDB::block_hash_ref` is seeded from authenticated data only: the
    // first block's parent (`F-1`) resolves to `before_ring[255]` (the owner's
    // parent slot of the L1-pinned ring), and every intra-batch parent resolves
    // to the guest's own computed header hash inserted after the prior block ran.
    // Reading the parent from that map closes the forge for the first block and
    // makes intra-batch chaining match native.
    let parent_hash = if block.number >= 1 {
        cache_db
            .db
            .block_hash_ref(block.number - 1)
            .expect("ProvenDB::block_hash_ref is infallible")
    } else {
        B256::ZERO
    };


    let computed_header_hash = block_header::compute_block_header_hash(
        &parent_hash,
        &block.coinbase.into_array(),
        &tx_root,
        &receipts_root,
        block.number,
        block.gas_limit,
        total_gas_used,
        block.timestamp,
        &block.prev_randao,
        block.base_fee,
    );

    // If a block_header_hash was provided in input, verify it matches our computation
    if !block.block_header_hash.is_zero() {
        assert_eq!(
            computed_header_hash, block.block_header_hash,
            "computed block header hash {computed_header_hash} != input {}", block.block_header_hash
        );
    }

    // L2->L1 logs are computed from REVM's execution output (the L1Messenger
    // precompile at 0x8008 emits L1MessageSent events, reconstructed into
    // L2ToL1LogEntry), and it is those COMPUTED logs that feed the batch
    // commitment. The witness `block.l2_to_l1_logs` is not read here: comparing
    // it against the computed set authenticates nothing (both are guest-derived,
    // and the commitment ignores the witness copy).

    (
        BlockResult {
            block_number: block.number,
            computed_block_header_hash: computed_header_hash,
            tx_results,
            l2_to_l1_logs: computed_l2_to_l1_logs,
        },
        state_effects,
    )
}

/// Execute a block's transactions in the EVM and return tx results + L2→L1 logs.
/// State changes are written into the shared `cache_db`.
fn run_evm_block<DB: DatabaseRef>(
    chain_id: u64,
    spec_id: ZkSpecId,
    block: &BlockInput,
    cache_db: &mut CacheDB<DB>,
    max_tx_gas_limit: u64,
) -> (Vec<TxOutput>, Vec<B256>, Vec<L2ToL1LogEntry>, BlockStateEffects)
where
    DB::Error: core::fmt::Debug,
{
    let mut evm = <ZkContext<_>>::default()
        .with_db(cache_db)
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
        .build_zk();

    let mut tx_results = Vec::with_capacity(block.transactions.len());
    let mut tx_hashes = Vec::with_capacity(block.transactions.len());
    let mut l2_to_l1_logs = Vec::new();
    // Per-block write tracking: (first value seen when a slot was first
    // changed in this block, last value it was changed to). The write SET
    // must come from the execution journal, not from a cache-vs-pre-state
    // diff — a slot toggled and restored across blocks nets to zero against
    // the batch pre-state but is still a write entry in every native
    // per-block diff (and therefore in the batch tree update).
    let mut slot_writes: std::collections::HashMap<(Address, U256), (U256, U256)> =
        std::collections::HashMap::new();
    let mut destroyed_accounts: HashSet<Address> = HashSet::new();
    let mut deployed_accounts: HashSet<Address> = HashSet::new();

    for (tx_idx, tx_input) in block.transactions.iter().enumerate() {
        evm.0.ctx.chain.set_tx_number(tx_idx as u16);

        let (tx, tx_hash, _tx_type) = build_proven_tx(tx_input, block.gas_limit, max_tx_gas_limit);
        tx_hashes.push(tx_hash);

        match evm.transact(tx) {
            Ok(result_and_state) => {
                for (addr, account) in &result_and_state.state {
                    // EIP-6780: an account created and selfdestructed within
                    // the same tx is destroyed — its storage never reaches
                    // the tree. revm sets the SelfDestructed status only when
                    // destruction actually applies (post-Cancun: created in
                    // the same tx; revm-context journal/inner.rs EIP-6780
                    // gate), so this cannot skip a surviving account's
                    // writes: a pre-existing account's SELFDESTRUCT is a
                    // balance transfer that never sets the flag.
                    if account.is_selfdestructed() {
                        // `CacheDB::commit` clears the cache entry of a TOUCHED
                        // selfdestructed account, leaving it indistinguishable
                        // from a read of an absent account. Record the same set
                        // commit acts on, so post-execution verification can
                        // tell a destroyed account from an untouched one.
                        if account.is_touched() {
                            destroyed_accounts.insert(*addr);
                        }
                        continue;
                    }
                    // A create frame that committed at this address. revm sets
                    // the flag before the init code runs and clears it again on
                    // revert, so it marks exactly the deployments that
                    // completed — including one whose runtime code is empty,
                    // which native still materializes as deployed.
                    if account.is_created() {
                        deployed_accounts.insert(*addr);
                    }
                    for (slot, s) in &account.storage {
                        if s.is_changed() {
                            slot_writes
                                .entry((*addr, *slot))
                                .and_modify(|(_, last)| *last = s.present_value)
                                .or_insert((s.original_value, s.present_value));
                        }
                    }
                }
                let result = result_and_state.result.clone();
                evm.commit(result_and_state.state);
                for log in evm.0.ctx.chain.take_logs() {
                    l2_to_l1_logs.push(L2ToL1LogEntry {
                        l2_shard_id: log.l2_shard_id,
                        is_service: log.is_service,
                        tx_number_in_block: log.tx_number_in_block,
                        sender: log.sender,
                        key: log.key,
                        value: log.value,
                    });
                }
                tx_results.push(TxOutput {
                    success: result.is_success(),
                    gas_used: result.tx_gas_used(),
                    output: result.output().map(|b| b.to_vec()).unwrap_or_default(),
                });
            }
            Err(e) => panic!("transaction execution failed: {e:?}"),
        }
    }

    let storage_writes = slot_writes
        .into_iter()
        .filter(|(_, (first, last))| first != last)
        .map(|(key, (_, last))| (key, last))
        .collect();

    (
        tx_results,
        tx_hashes,
        l2_to_l1_logs,
        BlockStateEffects { storage_writes, destroyed_accounts, deployed_accounts },
    )
}
