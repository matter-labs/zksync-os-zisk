//! REVM-based block executor for ZKsync OS with merkle proof verification.
//!
//! Every storage and account read is verified against a merkle proof that
//! recovers the expected state root. Values come FROM the proofs, not from
//! a separate data path.

mod eip2935;
mod evm;
mod interop;
mod proven_db;
mod stream;
pub mod tx;
mod verify;

use std::collections::{HashMap, HashSet};

use revm::database::CacheDB;
use revm::primitives::B256;
use zksync_os_revm::ZkSpecId;

use crate::commitment;
use crate::commitment::BatchOutputLayout;
use crate::types::*;

/// The lowest L1 protocol minor an AtlasV4 batch may carry.
///
/// The 0.4.0 tree names 32 and marks the value a draft, and the server still
/// routes minor 32 to the AtlasV3 execution version, so AtlasV3 accepts 32 as
/// well. Once the release fixes the protocol version, narrow the AtlasV3 arm of
/// the cross-check to 31 and pin AtlasV4 to exactly this value, so the two
/// ranges stop overlapping.
const ATLAS_V4_MIN_PROTOCOL_MINOR: u32 = 32;

/// Ergs charged per unit of gas (zksync-os `evm_interpreter::ERGS_PER_GAS`).
/// Gas is metered in ergs, so a gas limit above `u64::MAX / ERGS_PER_GAS`
/// overflows the erg counter.
const ERGS_PER_GAS: u64 = 256;

/// The largest block gas limit native accepts (`zk_ee` `MAX_BLOCK_GAS_LIMIT`).
const MAX_BLOCK_GAS_LIMIT: u64 = u64::MAX / ERGS_PER_GAS;

/// The largest per-transaction gas limit native accepts (`zk_ee`
/// `MAX_TX_GAS_LIMIT`).
const MAX_TX_GAS_LIMIT: u64 = MAX_BLOCK_GAS_LIMIT;

/// The EIP-7825 single-transaction gas limit, which is both the default
/// chain-config per-transaction cap and the floor for any configured value
/// (`zk_ee` `DEFAULT_MAX_TX_GAS_LIMIT`). A chain may raise the cap above
/// Ethereum's limit but must not set it below.
const DEFAULT_MAX_TX_GAS_LIMIT: u64 = 1 << 24;

/// Execute a batch with full merkle proof verification and compute the
/// BatchPublicInput hash matching the server/L1 format.
pub fn execute_and_commit(input: &BatchInput) -> (BatchOutput, B256) {
    let (output, commitment, _, _, _) = execute_and_commit_inner(input);
    (output, commitment)
}

/// Same as `execute_and_commit` but also returns the three commitment
/// sub-components for debugging.
pub fn execute_and_commit_debug(input: &BatchInput) -> (BatchOutput, B256, B256, B256, B256) {
    execute_and_commit_inner(input)
}

fn execute_and_commit_inner(input: &BatchInput) -> (BatchOutput, B256, B256, B256, B256) {
    let spec_id = resolve_spec_and_validate(input);
    // Build the proof-verified DB by collecting every proof at once (this holds
    // all merkle siblings resident). The streaming entry point below builds the
    // same DB proof-by-proof; both share the execution/commitment core.
    let proven_db = proven_db::build_proven_db(input);
    run_execution_and_commit(input, spec_id, proven_db)
}

/// Assert the wire-format version, resolve the spec id, and validate the block
/// sequence. Shared by the collecting and streaming entry points.
fn resolve_spec_and_validate(input: &BatchInput) -> ZkSpecId {
    assert_eq!(
        input.version,
        crate::types::BATCH_INPUT_VERSION,
        "unsupported BatchInput wire-format version {} (this guest understands {})",
        input.version,
        crate::types::BATCH_INPUT_VERSION,
    );
    let spec_id = match input.spec_id {
        0 => ZkSpecId::AtlasV1,
        1 => ZkSpecId::AtlasV2,
        2 => ZkSpecId::AtlasV3,
        3 => ZkSpecId::AtlasV4,
        _ => panic!("unknown spec_id: {}", input.spec_id),
    };
    // `spec_id` is the ZKsync OS state transition function tier and the single
    // source of truth for every formula the guest computes.
    // `protocol_version_minor` is the L1 protocol version, a separate axis.
    // Native never emits a pair that disagrees, so reject an inconsistent pair
    // and keep an operator from combining one spec's execution rules with
    // another spec's commitment layout.
    let minor_ok = match spec_id {
        ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => input.protocol_version_minor <= 30,
        ZkSpecId::AtlasV3 => matches!(input.protocol_version_minor, 31 | 32),
        ZkSpecId::AtlasV4 => input.protocol_version_minor >= ATLAS_V4_MIN_PROTOCOL_MINOR,
    };
    assert!(
        minor_ok,
        "inconsistent spec_id/protocol_version_minor: spec_id={} ({spec_id:?}), minor={}",
        input.spec_id, input.protocol_version_minor,
    );
    validate_block_sequence(input, spec_id);
    spec_id
}

/// Execute every block against the proof-verified `proven_db` and compute the
/// batch commitment. This is the shared core: `execute_and_commit_inner`
/// (collecting path) and `execute_and_commit_streaming` (streaming path) both funnel a
/// fully built `ProvenDB` plus the (possibly proof-stripped) `BatchInput`
/// through here, so the two paths produce a byte-identical commitment.
///
/// `input.blocks[].storage_proofs` is NEVER read here — only
/// `build_proven_db`/streaming consume it — so the streaming path may pass
/// blocks whose proofs have already been verified and dropped.
fn run_execution_and_commit(
    input: &BatchInput,
    spec_id: ZkSpecId,
    proven_db: proven_db::ProvenDB,
) -> (BatchOutput, B256, B256, B256, B256) {
    let meta = &input.batch_meta;
    let mut cache_db = CacheDB::new(proven_db);

    // Authenticate the pre-state block-hash ring against the L1-pinned
    // `block_hashes_blake_before` before execution begins. The returned
    // `before_ring` is the authenticated 256-entry history: any slot forgery
    // changes its Blake2s commitment away from the pinned value, so passing this
    // check pins every slot. It anchors both the BLOCKHASH map (seeded next) and
    // the after-ring (rebuilt below).
    let first_block = input.blocks.first().unwrap();
    let before_ring = verify_block_hashes_blake_before(meta, first_block);

    // Seed the BLOCKHASH map from that authenticated ring. Pre-batch numbers
    // resolve to the L1-pinned history; intra-batch numbers are added inside the
    // loop as each block's header hash is computed in-guest. A raw witness
    // `block_hashes` entry never reaches the map, so a later block cannot inject
    // a forged historical hash for a pre-batch slot.
    cache_db
        .db
        .set_block_hashes(proven_db::pre_batch_block_hashes(&before_ring, first_block.number));

    let mut block_results = Vec::with_capacity(input.blocks.len());
    let mut computed_block_hashes: HashMap<u64, B256> = HashMap::new();

    // Batch write set: union of the per-block net storage changes, each key
    // carrying the value of its last change (matches the native tree update,
    // which merges per-block diffs — including writes that net to zero
    // against the batch pre-state).
    let mut storage_writes: HashMap<(revm::primitives::Address, revm::primitives::U256), revm::primitives::U256> =
        HashMap::new();
    // Accounts destruction removed. `CacheDB` leaves a destroyed account
    // indistinguishable from an account a read found absent, so the write-map
    // verification below takes the distinction from this journal-derived set.
    let mut destroyed_accounts: HashSet<revm::primitives::Address> = HashSet::new();
    // Accounts a deployment completed at. `CacheDB` keeps no record of a
    // deployment, so the write-map verification below takes this signal from
    // the execution journal as well: it decides which code encoding native
    // wrote for an account that ends the batch holding no code.
    let mut deployed_accounts: HashSet<revm::primitives::Address> = HashSet::new();
    // EIP-7825 caps a transaction's own gas limit from AtlasV4 on. AtlasV1
    // through AtlasV3 bound an L2 transaction by the block gas limit alone, so
    // the chain-config cap stays off for them: an in-guest rejection that
    // native does not perform makes a legitimate batch unprovable.
    let max_tx_gas_limit = ZkSpecId::AtlasV4
        .is_enabled_in(spec_id)
        .then_some(meta.max_tx_gas_limit);
    for block in &input.blocks {
        verify_intra_batch_hashes(block, &computed_block_hashes);

        let (result, state_effects) = evm::execute_block_proven(
            input.chain_id, spec_id, block, &mut cache_db, max_tx_gas_limit,
        );
        // Feed the block's own computed header hash back into the BLOCKHASH map
        // so a later block's BLOCKHASH read resolves to this authenticated value.
        cache_db
            .db
            .insert_block_hash(block.number, result.computed_block_header_hash);
        computed_block_hashes.insert(block.number, result.computed_block_header_hash);
        block_results.push(result);
        storage_writes.extend(state_effects.storage_writes);
        destroyed_accounts.extend(state_effects.destroyed_accounts);
        deployed_accounts.extend(state_effects.deployed_accounts);
    }

    let output = BatchOutput { chain_id: input.chain_id, block_results };

    // Build complete write map (storage + 0x8003 account properties) and verify.
    // Non-executed account-property writes (system force-deploys) are accepted
    // only in upgrade batches; `upgrade_tx_hash` is authenticated below to be
    // nonzero iff an Upgrade tx is present, so this gate cannot be forged on.
    let revm_writes = verify::build_revm_write_map(
        &storage_writes,
        &destroyed_accounts,
        &deployed_accounts,
        &cache_db,
        &meta.account_preimages_after,
        !meta.upgrade_tx_hash.is_zero(),
    );
    let (tree_root_after, new_leaf_count) = verify::verify_tree_update(meta, &revm_writes);

    // `before_ring` (authenticated above, before execution) anchors both the
    // BLOCKHASH map and the after-ring.

    // State before.
    let state_before = commitment::state_commitment_hash(
        &meta.tree_root_before, meta.leaf_count_before,
        meta.block_number_before, &meta.block_hashes_blake_before,
        meta.last_block_timestamp_before,
    );

    // State after.
    //
    // `block_hashes_blake_after` is reconstructed from AUTHENTICATED data only,
    // never from the witness `meta.previous_block_hashes` (which the operator
    // could forge; the pre-refactor code folded it verbatim and it was checked
    // only by a cross-check with two escape hatches). The after-ring's pre-batch
    // slots come from the L1-anchored `before_ring`; its intra-batch slots come
    // from the guest's own `computed_block_hashes`. So `state_after` is a
    // deterministic function of authenticated inputs, exactly like the before-ring.
    let last_block = input.blocks.last().unwrap();
    let last_block_result = output.block_results.last().unwrap();
    let block_hashes_blake_after = reconstruct_block_hashes_blake_after(
        first_block.number,
        last_block.number,
        &before_ring,
        &computed_block_hashes,
        &last_block_result.computed_block_header_hash,
    );
    let state_after = commitment::state_commitment_hash(
        &tree_root_after, new_leaf_count,
        last_block.number, &block_hashes_blake_after, last_block.timestamp,
    );

    // Batch output hash
    let mut l1_tx_hashes = Vec::new();
    let mut l2_to_l1_encoded_logs = Vec::new();
    let mut num_l1_txs: u64 = 0;
    let mut num_l2_txs: u64 = 0;
    let mut num_upgrade_txs: u64 = 0;
    let mut interop_roots_rolling_hash = B256::ZERO;
    // The `InteropRoot` tuple gains a creation timestamp at AtlasV4, which moves
    // both the import selector and the rolling-hash preimage.
    let import_abi = if ZkSpecId::AtlasV4.is_enabled_in(spec_id) {
        tx::InteropImportAbi::WithTimestamp
    } else {
        tx::InteropImportAbi::WithoutTimestamp
    };

    for block in &input.blocks {
        for tx in &block.transactions {
            match &tx.auth {
                TxAuth::L1 { tx_hash, .. } => {
                    l1_tx_hashes.push(*tx_hash);
                    num_l1_txs += 1;
                }
                TxAuth::Upgrade { tx_hash, .. } => {
                    assert_eq!(
                        *tx_hash, meta.upgrade_tx_hash,
                        "upgrade tx hash {tx_hash} != batch_meta.upgrade_tx_hash {}",
                        meta.upgrade_tx_hash
                    );
                    num_upgrade_txs += 1;
                }
                TxAuth::L2 { .. } => {
                    num_l2_txs += 1;
                }
                TxAuth::System { tx_hash, encoded_2718 } => {
                    // System txs count as L2 txs in the batch commitment;
                    // interop-root imports additionally fold every imported
                    // root into the dependency-roots rolling hash. Both facts
                    // are derived from the hash-authenticated encoding.
                    num_l2_txs += 1;
                    tx::fold_system_tx_interop_roots(
                        tx_hash,
                        encoded_2718,
                        import_abi,
                        &mut interop_roots_rolling_hash,
                    );
                }
            }
        }
    }
    // Authenticate `upgrade_tx_hash` bidirectionally: it is folded into
    // `batch_output_hash`, so an operator must not be able to set it on a
    // non-upgrade batch (or drop the Upgrade tx while it stays nonzero). The
    // loop above already pins any Upgrade tx's hash to it; here we close the
    // other direction: it is nonzero iff exactly one Upgrade tx is present.
    // (This also authenticates the force-deploy gate in `build_revm_write_map`.)
    assert!(
        num_upgrade_txs <= 1,
        "at most one Upgrade tx per batch, found {num_upgrade_txs}"
    );
    assert_eq!(
        num_upgrade_txs == 1,
        !meta.upgrade_tx_hash.is_zero(),
        "upgrade_tx_hash must be nonzero iff an Upgrade tx is present \
         (upgrade txs: {num_upgrade_txs}, upgrade_tx_hash: {})",
        meta.upgrade_tx_hash,
    );

    for br in &output.block_results {
        for log in &br.l2_to_l1_logs {
            l2_to_l1_encoded_logs.push(log.encode());
        }
    }

    // Authenticate the two interop scalars instead of trusting the witness.
    // Native reads both as storage reads of fixed system-contract slots at batch
    // boundaries (block_flow/zk/post_tx_op::read_batch_context_inputs); the guest
    // reproduces those reads against the server-supplied slot proofs (`interop`),
    // so `multichain_root`/`sl_chain_id` are DERIVED, not inherited. A proof
    // inconsistent with the pinned root fails there, rejecting a forged scalar.
    let commits_interop = ZkSpecId::AtlasV3.is_enabled_in(spec_id);
    let derived_interop = if commits_interop {
        let proofs = meta.interop_proofs.as_ref().expect(
            "v31 batch is missing interop_proofs: the server must supply the \
             sl_chain_id / multichain_root slot proofs",
        );
        // multichain_root: post-state read of MessageRoot 0x10005 against the
        // in-guest-computed tree_root_after (zero unless a settlement layer).
        let multichain_root = interop::derive_multichain_root(proofs, &tree_root_after);
        // sl_chain_id: SystemContext 0x800b slot 0, read at post-state against the
        // in-guest-computed tree_root_after. Post-state is used for every batch,
        // including upgrades that write the slot this batch, so the value is
        // always derived from an authenticated proof rather than inherited from
        // the witness scalar.
        let sl_chain_id = interop::derive_sl_chain_id(&proofs.sl_chain_id, &tree_root_after);
        // The interop commitment tree root at both batch boundaries: two more
        // leaves of the AtlasV4 chain batch root, read at the L1-pinned
        // pre-state root and at the in-guest-computed post-state root.
        let commitment_tree_roots =
            ZkSpecId::AtlasV4.is_enabled_in(spec_id).then(|| {
                let proofs = proofs.commitment_tree.as_ref().expect(
                    "AtlasV4 batch is missing the interop commitment tree proofs: \
                     the server must supply the 0x10012 height and root slot \
                     proofs at the pre-batch and post-batch states",
                );
                interop::derive_interop_commitment_tree_roots(
                    proofs,
                    &meta.tree_root_before,
                    &tree_root_after,
                )
            });
        interop::DerivedInteropValues {
            multichain_root,
            sl_chain_id,
            commitment_tree_roots,
        }
    } else {
        // v30 commits none of these: multichain folds in as zero below,
        // sl_chain_id is absent from the v30 batch-output layout, and the chain
        // batch root of that line carries no commitment tree leaf.
        interop::DerivedInteropValues {
            multichain_root: B256::ZERO,
            sl_chain_id: meta.sl_chain_id,
            commitment_tree_roots: None,
        }
    };

    let priority_ops_hash = commitment::priority_ops_rolling_hash(&l1_tx_hashes);
    let l2_logs_local_root = commitment::l2_to_l1_logs_root(&l2_to_l1_encoded_logs);
    // The chain batch root: AtlasV4 folds four leaves into a height-3 keccak
    // tree, so a consumer can authenticate an interop commitment tree root
    // against it with a few hashes. AtlasV1 through AtlasV3 hash the logs root
    // and the multichain root alone. For protocol v30, multichain_root folds in
    // as zero (derived above); for v31+ it is the authenticated MessageRoot
    // aggregation root.
    let chain_batch_root_layout = if ZkSpecId::AtlasV4.is_enabled_in(spec_id) {
        commitment::ChainBatchRootLayout::HeightThreeMerkle
    } else {
        commitment::ChainBatchRootLayout::TwoPreimageKeccak
    };
    // The two roots are derived for exactly the specs whose layout carries
    // them, so the zero fallback only ever reaches the two-preimage form, which
    // reads neither.
    let commitment_tree_roots = derived_interop.commitment_tree_roots.unwrap_or(
        interop::InteropCommitmentTreeRoots {
            begin: B256::ZERO,
            end: B256::ZERO,
        },
    );
    let l2_logs_root_hash = commitment::chain_batch_root(
        chain_batch_root_layout,
        &l2_logs_local_root,
        &derived_interop.multichain_root,
        &commitment_tree_roots.begin,
        &commitment_tree_roots.end,
    );

    let da_commitment = match meta.da_commitment_scheme {
        0 | 1 => B256::ZERO,                                          // None / EmptyNoDA
        2 | 3 => commitment::da_commitment_calldata(&meta.pubdata),       // PubdataKeccak / BlobsAndPubdataKeccak
        4 => commitment::da_commitment_blobs(&meta.blob_versioned_hashes), // BlobsZKsyncOS
        _ => panic!("unsupported DA commitment scheme: {}", meta.da_commitment_scheme),
    };

    // Batch output hash — the layout of the spec that executed the batch.
    let batch_output_layout = match spec_id {
        ZkSpecId::AtlasV1 | ZkSpecId::AtlasV2 => BatchOutputLayout::V30,
        ZkSpecId::AtlasV3 => BatchOutputLayout::V31,
        ZkSpecId::AtlasV4 => BatchOutputLayout::AtlasV4,
    };
    let batch_hash = commitment::batch_output_hash_native(
        batch_output_layout,
        input.chain_id,
        input.blocks.first().unwrap().timestamp,
        last_block.timestamp,
        meta.da_commitment_scheme,
        &da_commitment,
        num_l1_txs,
        num_l2_txs,
        &priority_ops_hash,
        &l2_logs_root_hash,
        &meta.upgrade_tx_hash,
        &interop_roots_rolling_hash,
        derived_interop.sl_chain_id,
    );

    // The top-level public input commits the chain config from AtlasV4 on
    // (`BatchPublicInput::hash`). AtlasV1 through AtlasV3 hash three words:
    // native on those lines carries no `chain_config_hash` field, so a fourth
    // word would commit a value the first prover never computes, and L1 could
    // not gate the two lanes against each other.
    let chain_config_hash = ZkSpecId::AtlasV4.is_enabled_in(spec_id).then(|| {
        commitment::chain_config_hash(
            input.chain_id,
            meta.fri_proof_verification_enabled,
            meta.max_tx_gas_limit,
            meta.pubdata_content,
        )
    });
    let commitment = commitment::batch_public_input_hash(
        &state_before,
        &state_after,
        chain_config_hash.as_ref(),
        &batch_hash,
    );
    (output, commitment, state_before, state_after, batch_hash)
}

fn validate_block_sequence(input: &BatchInput, spec_id: ZkSpecId) {
    let meta = &input.batch_meta;
    assert!(!input.blocks.is_empty(), "batch must contain at least one block");
    validate_atlas_v4_block_invariants(input, spec_id);
    assert!(
        input.blocks[0].number == meta.block_number_before + 1,
        "first block number {} must follow block_number_before {}",
        input.blocks[0].number, meta.block_number_before,
    );
    // Cross-batch timestamp monotonicity. `state_before` commits
    // `meta.last_block_timestamp_before` (the previous batch's last block
    // timestamp). The first block must not go before that value. Native applies
    // the same rule per block in `post_tx_op` (`block_timestamp() >=
    // last_block_timestamp`): the first block compares against this committed
    // pre-batch value, and each later block compares against the block before
    // it. The window loop below covers the later blocks; this assertion covers
    // the batch boundary that the loop cannot see. Both use the same
    // non-decreasing relation (`>=`), so equal timestamps stay valid.
    assert!(
        input.blocks[0].timestamp >= meta.last_block_timestamp_before,
        "first block timestamp {} goes before the previous batch's last block timestamp {}",
        input.blocks[0].timestamp, meta.last_block_timestamp_before,
    );
    for w in input.blocks.windows(2) {
        assert!(w[1].number == w[0].number + 1, "block numbers must be consecutive");
        assert!(w[1].timestamp >= w[0].timestamp, "block timestamps must be non-decreasing");
    }
    validate_expected_tree_roots(input);
}

/// The block-level and chain-config invariants native checks once per block in
/// `metadata_op`, plus the EIP-2935 block-number rule. All are AtlasV4 rules:
/// `ChainConfig` and the pre-block EIP-2935 step exist only on that line, and an
/// in-guest rejection an older native never performs would make a legitimate
/// batch unprovable.
///
/// - `ChainConfig::validate`: the EIP-7825 per-transaction cap may be raised
///   above Ethereum's limit but never lowered below it. The value is committed
///   in `chain_config_hash` and caps every L2 transaction, so a config native
///   refuses to load must not reach either consumer.
/// - `PubdataContent::try_from`: the mode id is 0 or 1. Native rejects any
///   other byte while deserializing the chain config, so an out-of-range value
///   must fail loudly here rather than reach `chain_config_hash` as a word
///   native never commits.
/// - `block_gas_limit <= MAX_BLOCK_GAS_LIMIT` and
///   `min(block_gas_limit, max_tx_gas_limit) <= MAX_TX_GAS_LIMIT`: an over-large
///   limit aborts the whole block in native.
/// - The EIP-2935 pre-block step errors on block number 0, so an AtlasV4 chain
///   has no executable block 0.
fn validate_atlas_v4_block_invariants(input: &BatchInput, spec_id: ZkSpecId) {
    if !ZkSpecId::AtlasV4.is_enabled_in(spec_id) {
        return;
    }
    let max_tx_gas_limit = input.batch_meta.max_tx_gas_limit;
    assert!(
        max_tx_gas_limit >= DEFAULT_MAX_TX_GAS_LIMIT,
        "chain max_tx_gas_limit {max_tx_gas_limit} is below the EIP-7825 \
         single-transaction gas limit {DEFAULT_MAX_TX_GAS_LIMIT}",
    );
    let pubdata_content = input.batch_meta.pubdata_content;
    assert!(
        matches!(
            pubdata_content,
            PUBDATA_CONTENT_FULL | PUBDATA_CONTENT_LOGS_ONLY
        ),
        "unknown chain pubdata_content {pubdata_content}: native accepts \
         {PUBDATA_CONTENT_FULL} (full pubdata) and {PUBDATA_CONTENT_LOGS_ONLY} \
         (logs only)",
    );
    for block in &input.blocks {
        assert!(
            block.number >= 1,
            "block 0 is not executable at AtlasV4: the EIP-2935 pre-block step \
             errors on block number 0",
        );
        assert!(
            block.gas_limit <= MAX_BLOCK_GAS_LIMIT,
            "block {} gas limit {} exceeds the protocol maximum {MAX_BLOCK_GAS_LIMIT}",
            block.number,
            block.gas_limit,
        );
        let individual_tx_gas_limit = block.gas_limit.min(max_tx_gas_limit);
        assert!(
            individual_tx_gas_limit <= MAX_TX_GAS_LIMIT,
            "block {} per-transaction gas limit {individual_tx_gas_limit} exceeds \
             the protocol maximum {MAX_TX_GAS_LIMIT}",
            block.number,
        );
    }
}

/// SOUNDNESS: every storage/account read is authenticated against the
/// single L1-pinned pre-state root `meta.tree_root_before`. The witness scalar
/// `block.expected_tree_root` is NOT trusted as a read-authentication root
/// (`proven_db::expected_root_for_block` ignores it); it is retained on the wire
/// only for version compatibility and must therefore be zero or exactly equal to
/// `tree_root_before`. Reject anything else up front so a forged per-block read
/// root fails with a named error on BOTH the collecting and streaming paths —
/// including for a proofless block, where the per-proof root check would never
/// fire.
fn validate_expected_tree_roots(input: &BatchInput) {
    let pinned = input.batch_meta.tree_root_before;
    for block in &input.blocks {
        assert!(
            block.expected_tree_root.is_zero() || block.expected_tree_root == pinned,
            "block {} expected_tree_root {} is neither zero nor the L1-pinned \
             tree_root_before {}: storage reads must authenticate against the \
             pinned pre-state root, never a witness-chosen per-block root",
            block.number,
            block.expected_tree_root,
            pinned,
        );
    }
}

fn verify_intra_batch_hashes(block: &BlockInput, computed: &HashMap<u64, B256>) {
    for &(num, hash) in &block.block_hashes {
        if let Some(&expected) = computed.get(&num) {
            assert_eq!(hash, expected,
                "intra-batch block hash mismatch for block {num}: \
                 server={hash}, computed={expected}");
        }
    }
}

/// Authenticate the pre-batch historical block-hash ring against the L1-pinned
/// `block_hashes_blake_before` and return the authenticated 256-entry ring.
///
/// `block_hashes_blake_before` is part of `state_before`, which L1 chains to the
/// previous batch's `state_after`, so it is trustworthy. The ring the guest
/// actually uses is the separate witness field `first_block.block_hashes`: it
/// feeds the `BLOCKHASH` opcode (via `ProvenDB::block_hash_ref`), supplies the
/// first block's parent hash (`evm.rs`), and (via the returned ring) anchors the
/// pre-batch slots of `block_hashes_blake_after`. `verify_intra_batch_hashes`
/// covers only blocks computed within the batch.
///
/// A malicious sequencer could otherwise supply a forged-but-internally-
/// consistent historical ring, making `BLOCKHASH(old_block)` return arbitrary
/// values. Rebuilding the ring from the witnessed history and asserting its
/// Blake2s commitment equals the pinned value anchors every slot: any single
/// forged slot changes the commitment. The reconstructed ring is returned so the
/// caller can reuse those authenticated slots when building the after-ring.
pub(crate) fn verify_block_hashes_blake_before(
    meta: &BatchMeta,
    first_block: &BlockInput,
) -> [B256; 256] {
    let ring = reconstruct_ring(first_block.number, &first_block.block_hashes);
    let reconstructed = commitment::block_hashes_blake(&ring[..255], &ring[255]);
    assert_eq!(
        reconstructed, meta.block_hashes_blake_before,
        "pre-state block-hash ring is not authenticated by the L1-pinned \
         block_hashes_blake_before: reconstructed={reconstructed}, \
         pinned={}",
        meta.block_hashes_blake_before,
    );
    ring
}

/// Rebuild the 256-entry block-hash context ring owned by `owner_block_number`
/// from a witnessed `(block_number, hash)` history.
///
/// The ring covers blocks `[owner-256, owner-1]`, placed at
/// `index = block_number + 256 - owner` (oldest at 0, the owner's parent at 255).
/// Out-of-window entries are ignored and empty slots stay zero (genesis padding).
/// This is the same layout the server hashes for `block_hashes_blake_before`.
fn reconstruct_ring(owner_block_number: u64, hashes: &[(u64, B256)]) -> [B256; 256] {
    let mut ring = [B256::ZERO; 256];
    for &(num, hash) in hashes {
        if num < owner_block_number && owner_block_number - num <= 256 {
            let idx = (num + 256 - owner_block_number) as usize;
            ring[idx] = hash;
        }
    }
    ring
}

/// Canonical Blake2s commitment of the pre-state block-hash ring. Kept as a
/// crate-visible helper for the block-hash authentication tests.
#[cfg(test)]
pub(crate) fn reconstruct_block_hashes_blake_before(
    first_block_number: u64,
    first_block_hashes: &[(u64, B256)],
) -> B256 {
    let ring = reconstruct_ring(first_block_number, first_block_hashes);
    commitment::block_hashes_blake(&ring[..255], &ring[255])
}

/// Rebuild `block_hashes_blake_after` from authenticated data only, so the after
/// block-hash ring folded into `state_after` never depends on the untrusted
/// witness `meta.previous_block_hashes`.
///
/// The after-ring is the 256-entry BLOCKHASH context for the last block `L`,
/// covering blocks `[L-255, L]`. Position `p` holds the hash of block
/// `n = L - 255 + p`:
/// - `p == 255` is block `L` itself: the guest's `computed_last_header`.
/// - intra-batch (`F <= n <= L-1`): the guest's own `computed_block_hashes[n]`,
///   unconditionally (never gated on a witness `block_hashes` listing, which was
///   the multi-block "windowing" seam).
/// - pre-batch (`0 <= n < F`): the corresponding slot of the L1-authenticated
///   `before_ring` (the pre-batch portion `[L-255, F-1]` of the after-window is
///   always inside the before-window `[F-256, F-1]`, so every such slot exists).
///   Block 0 (genesis) is a real block. It falls in this branch, so the guest
///   reads its authenticated hash from `before_ring[255]` and does not zero it.
/// - pre-genesis padding (`n < 0`): zero.
///
/// For an honest batch this equals `block_hashes_blake(&meta.previous_block_hashes,
/// &computed_last_header)`, so the committed value is unchanged; it only stops
/// depending on the forgeable witness (closing both the zero-guard and the
/// windowing seams, and the `L < 255` early-chain branch).
pub(crate) fn reconstruct_block_hashes_blake_after(
    first_block_number: u64,
    last_block_number: u64,
    before_ring: &[B256; 256],
    computed_block_hashes: &HashMap<u64, B256>,
    computed_last_header: &B256,
) -> B256 {
    let f = first_block_number;
    let l = last_block_number;
    let mut after = [B256::ZERO; 256];
    after[255] = *computed_last_header;
    for (p, slot) in after.iter_mut().enumerate().take(255) {
        // Block number represented at position p (signed to handle early chain).
        let n = l as i128 - 255 + p as i128;
        if n < 0 {
            continue; // Pre-genesis padding stays zero. Block 0 (genesis) is real.
        }
        let n = n as u64;
        if n >= f && n <= l - 1 {
            // Intra-batch: use the guest's own computed header hash.
            *slot = *computed_block_hashes
                .get(&n)
                .expect("intra-batch block hash must be computed in-guest");
        } else if n < f {
            // Pre-batch: read from the L1-authenticated before-ring.
            let before_idx = n as i128 + 256 - f as i128;
            if (0..256).contains(&before_idx) {
                *slot = before_ring[before_idx as usize];
            }
        }
    }
    commitment::block_hashes_blake(&after[..255], &after[255])
}

/// Execute a batch from bincode-serialized BatchInput bytes.
/// Returns the output and batch commitment hash.
/// Used by the server to compute ZiSK commitments in-process.
pub fn execute_and_commit_from_bincode(
    bincode_data: &[u8],
) -> Result<(BatchOutput, B256), String> {
    let batch_input: BatchInput =
        crate::wire::decode(bincode_data).map_err(|e| format!("deserialize: {e}"))?;
    Ok(execute_and_commit(&batch_input))
}

/// Streaming execution from bincode-serialized `BatchInput` bytes.
///
/// This is the memory-lean entry point the ZiSK guest uses. Instead of
/// `bincode::deserialize::<BatchInput>` (which materialises EVERY merkle
/// sibling on the heap before verification — the read-spam OOM floor), it
/// parses the wire format with a `DeserializeSeed` tower that consumes the
/// `storage_proofs` sequence element-by-element: each proof is deserialized,
/// verified against the block's pre-state root, its value extracted into the
/// `ProvenDB` under construction, and then DROPPED before the next proof is
/// read. The siblings are therefore never all resident at once — the resident
/// set holds only the small verified value map.
///
/// The wire format is unchanged: the server still `bincode`-serialises
/// `BatchInput` exactly as before. Only the guest's *parsing* differs, and the
/// resulting `ProvenDB` + commitment are byte-identical to the collecting path
/// (`execute_and_commit_from_bincode`). See `stream.rs`.
pub fn execute_and_commit_streaming(
    bincode_data: &[u8],
) -> Result<(BatchOutput, B256), String> {
    let (input, proven_db) = stream::stream_deserialize_and_build_db(bincode_data)?;
    let spec_id = resolve_spec_and_validate(&input);
    let (output, commitment, _, _, _) = run_execution_and_commit(&input, spec_id, proven_db);
    Ok((output, commitment))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BatchInput, BatchMeta, BlockInput};

    /// A block that carries the fields `validate_block_sequence` reads
    /// (`number`, `timestamp`, `expected_tree_root`). The rest hold neutral
    /// values.
    fn block_at(number: u64, timestamp: u64) -> BlockInput {
        BlockInput {
            number,
            timestamp,
            base_fee: 0,
            gas_limit: 0,
            coinbase: revm::primitives::Address::ZERO,
            prev_randao: B256::ZERO,
            transactions: vec![],
            account_preimages: vec![],
            block_hashes: vec![],
            storage_proofs: vec![],
            block_header_hash: B256::ZERO,
            l2_to_l1_logs: vec![],
            expected_tree_root: B256::ZERO,
        }
    }

    /// A batch whose sequence-relevant `batch_meta` fields are set. Only
    /// `validate_block_sequence` reads them; every other field is neutral.
    fn batch(
        block_number_before: u64,
        last_block_timestamp_before: u64,
        blocks: Vec<BlockInput>,
    ) -> BatchInput {
        BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 1,
            spec_id: 2,
            protocol_version_minor: 31,
            blocks,
            bytecodes: vec![],
            batch_meta: BatchMeta {
                tree_root_before: B256::ZERO,
                leaf_count_before: 0,
                block_number_before,
                last_block_timestamp_before,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0,
                blob_versioned_hashes: vec![],
                tree_update: None,
                account_preimages_after: vec![],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
                pubdata_content: 0,
                interop_proofs: None,
            },
        }
    }

    /// A batch whose first block goes before the previous batch's last block
    /// timestamp must be rejected. The previous batch ended at 100; the first
    /// block claims 99.
    #[test]
    #[should_panic(expected = "goes before the previous batch")]
    fn rejects_first_block_before_previous_batch() {
        validate_block_sequence(&batch(0, 100, vec![block_at(1, 99)]), ZkSpecId::AtlasV3);
    }

    /// A compliant batch still passes: the first block timestamp equals the
    /// previous batch's last timestamp (non-decreasing allows equality), and a
    /// later block keeps the timestamp non-decreasing across the boundary.
    #[test]
    fn accepts_first_block_at_or_after_previous_batch() {
        validate_block_sequence(&batch(0, 100, vec![block_at(1, 100)]), ZkSpecId::AtlasV3);
        validate_block_sequence(
            &batch(0, 100, vec![block_at(1, 101), block_at(2, 101)]),
            ZkSpecId::AtlasV3,
        );
    }

    /// A batch carrying the `(spec_id, protocol_version_minor)` pair, otherwise
    /// compliant, for the dispatch cross-check.
    fn dispatch_batch(spec_id: u8, protocol_version_minor: u32) -> BatchInput {
        let mut input = batch(0, 0, vec![block_at(1, 1)]);
        input.spec_id = spec_id;
        input.protocol_version_minor = protocol_version_minor;
        input
    }

    /// Every wire spec byte native emits resolves, and each resolves to its own
    /// tier.
    #[test]
    fn resolves_every_known_spec_byte() {
        for (byte, minor, expected) in [
            (0u8, 30u32, ZkSpecId::AtlasV1),
            (1, 30, ZkSpecId::AtlasV2),
            (2, 31, ZkSpecId::AtlasV3),
            (2, 32, ZkSpecId::AtlasV3),
            (3, 32, ZkSpecId::AtlasV4),
            (3, 33, ZkSpecId::AtlasV4),
        ] {
            assert_eq!(
                resolve_spec_and_validate(&dispatch_batch(byte, minor)),
                expected,
                "spec byte {byte} with minor {minor}",
            );
        }
    }

    /// A spec byte no release emits is rejected rather than mapped to a
    /// neighbour.
    #[test]
    #[should_panic(expected = "unknown spec_id: 4")]
    fn rejects_an_unknown_spec_byte() {
        resolve_spec_and_validate(&dispatch_batch(4, 32));
    }

    /// An AtlasV4 batch claiming a protocol minor below the AtlasV4 range is
    /// rejected: the pair would combine AtlasV4 execution rules with an older
    /// line's L1 protocol version.
    #[test]
    #[should_panic(expected = "inconsistent spec_id/protocol_version_minor")]
    fn rejects_atlas_v4_below_its_protocol_minor() {
        resolve_spec_and_validate(&dispatch_batch(3, 31));
    }

    /// An AtlasV3 batch claiming a protocol minor above the AtlasV3 range is
    /// rejected. The previous cross-check accepted every minor at or above 31
    /// for AtlasV3.
    #[test]
    #[should_panic(expected = "inconsistent spec_id/protocol_version_minor")]
    fn rejects_atlas_v3_above_its_protocol_minor() {
        resolve_spec_and_validate(&dispatch_batch(2, 33));
    }

    /// An AtlasV1 or AtlasV2 batch claiming a v31 protocol minor is rejected.
    #[test]
    #[should_panic(expected = "inconsistent spec_id/protocol_version_minor")]
    fn rejects_atlas_v2_with_a_v31_protocol_minor() {
        resolve_spec_and_validate(&dispatch_batch(1, 31));
    }

    /// The wire-format version the previous guest understood is rejected with
    /// the named error, so a server that predates the ZKsync OS 0.5.0 input
    /// contract cannot feed this guest.
    #[test]
    #[should_panic(expected = "unsupported BatchInput wire-format version 4")]
    fn rejects_the_previous_wire_format_version() {
        let mut input = dispatch_batch(2, 31);
        input.version = 4;
        resolve_spec_and_validate(&input);
    }

    /// AtlasV4 has no executable block 0: native's EIP-2935 pre-block step
    /// errors there.
    #[test]
    #[should_panic(expected = "block 0 is not executable at AtlasV4")]
    fn rejects_block_zero_at_atlas_v4() {
        let mut input = dispatch_batch(3, 32);
        input.batch_meta.block_number_before = u64::MAX; // block 0 follows it
        input.blocks = vec![block_at(0, 1)];
        resolve_spec_and_validate(&input);
    }

    /// A chain config that sets the EIP-7825 per-transaction cap below
    /// Ethereum's limit is one native refuses to load.
    #[test]
    #[should_panic(expected = "is below the EIP-7825 single-transaction gas limit")]
    fn rejects_a_chain_cap_below_the_eip7825_limit() {
        let mut input = dispatch_batch(3, 32);
        input.batch_meta.max_tx_gas_limit = (1 << 24) - 1;
        resolve_spec_and_validate(&input);
    }

    /// A pubdata content mode native's `PubdataContent::try_from` rejects must
    /// not reach `chain_config_hash`, which would otherwise commit a word no
    /// native run produces.
    #[test]
    #[should_panic(expected = "unknown chain pubdata_content 2")]
    fn rejects_an_unknown_pubdata_content_mode() {
        let mut input = dispatch_batch(3, 32);
        input.batch_meta.pubdata_content = 2;
        resolve_spec_and_validate(&input);
    }

    /// A block gas limit above the protocol maximum aborts the block in native,
    /// so the guest must not prove it.
    #[test]
    #[should_panic(expected = "exceeds the protocol maximum")]
    fn rejects_a_block_gas_limit_above_the_protocol_maximum() {
        let mut input = dispatch_batch(3, 32);
        input.blocks[0].gas_limit = MAX_BLOCK_GAS_LIMIT + 1;
        resolve_spec_and_validate(&input);
    }

    /// The block-level limits are AtlasV4 rules, so an older spec keeps its
    /// previous behaviour.
    #[test]
    fn block_gas_limit_ceiling_does_not_reach_older_specs() {
        let mut input = dispatch_batch(2, 31);
        input.blocks[0].gas_limit = MAX_BLOCK_GAS_LIMIT + 1;
        input.batch_meta.max_tx_gas_limit = 0;
        assert_eq!(resolve_spec_and_validate(&input), ZkSpecId::AtlasV3);
    }
}
