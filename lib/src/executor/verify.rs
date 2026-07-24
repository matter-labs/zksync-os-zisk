//! Post-execution verification.
//!
//! Builds the complete write map (storage + 0x8003 account properties) from
//! REVM's CacheDB and verifies it against the tree_update merkle proof.

use std::collections::HashMap;

use revm::database::CacheDB;
use revm::DatabaseRef;
use revm::primitives::{Address, B256, KECCAK_EMPTY, U256};

use crate::account_props;
use crate::merkle;
use crate::types::*;
use super::proven_db::ProvenDB;

/// Build the complete write map: flat_key → new_value for both regular storage
/// writes and 0x8003 account-property writes. For 0x8003, the server provides
/// after-state preimages; we verify nonce/balance match REVM output, then use
/// blake2s(preimage) as the value.
pub(super) fn build_revm_write_map(
    storage_writes: &HashMap<(Address, U256), U256>,
    cache_db: &CacheDB<ProvenDB>,
    after_preimages: &[(Address, Vec<u8>)],
    is_upgrade_batch: bool,
) -> HashMap<B256, B256> {
    let proven_db = &cache_db.db;
    let after_map: HashMap<&Address, &Vec<u8>> = after_preimages.iter()
        .map(|(a, p)| (a, p)).collect();

    let mut writes = HashMap::new();

    // Regular storage writes come from the execution journal (per-block net
    // changes, merged batch-wide) — NOT from a cache-vs-pre-state diff,
    // which would drop writes that net to zero across the batch while the
    // native tree update still carries them.
    for ((addr, slot), value) in storage_writes {
        let slot_b256 = B256::from(slot.to_be_bytes::<32>());
        let flat_key = merkle::derive_flat_storage_key(&addr.into_array(), &slot_b256);
        writes.insert(flat_key, B256::from(value.to_be_bytes::<32>()));
    }

    // 0x8003 account-property writes. Every after-preimage the server
    // provides becomes a tree write with value blake2s(preimage), which
    // `verify_tree_update` checks against the merkle-authenticated tree entry
    // — so a forged preimage produces the wrong value and fails there.
    // Accounts changed only by a system force-deploy are absent from the REVM
    // cache; they rest on that tree authentication plus the code-field
    // self-consistency check below. For accounts REVM executed we also pin
    // nonce/balance to REVM's output.
    for (&addr, &after_preimage) in &after_map {
        let props = merkle::AccountProperties::decode(after_preimage);

        let executed = cache_db.cache.accounts.get(addr).filter(|a| {
            !matches!(
                a.account_state,
                revm::database::AccountState::None | revm::database::AccountState::NotExisting
            )
        });

        // Injection guard. An after-preimage for an account REVM never executed
        // is unconstrained by the nonce/balance pin below, so accepting it lets
        // an operator fabricate an account-property write (e.g. mint a balance
        // onto a dormant EOA). The only legitimate non-executed write is the
        // system force-deploy path, which is confined to upgrade batches (the
        // documented trusted hole). Outside an upgrade batch, reject it.
        assert!(
            executed.is_some() || is_upgrade_batch,
            "after-preimage for non-executed account {addr} outside an upgrade batch: \
             account-property writes must correspond to accounts changed by execution"
        );

        if let Some(db_account) = executed {
            let info = &db_account.info;
            assert_eq!(props.nonce, info.nonce,
                "after-preimage nonce mismatch for {addr}: preimage={}, revm={}",
                props.nonce, info.nonce);
            assert_eq!(U256::from_be_bytes(props.balance), info.balance,
                "after-preimage balance mismatch for {addr}");
        }

        // Code-derived fields are a pure function of the post-state code:
        // recompute them from the referenced code so a preimage cannot bind
        // wrong code to the account.
        let observable = props.observable_bytecode_hash;
        if observable == KECCAK_EMPTY || observable.is_zero() {
            // No observable code: never-deployed (all-zero fields) or
            // deployed-with-empty-code (native materializes every completed
            // deployment, empty code included). See `no_code_fields_valid`.
            assert!(account_props::no_code_fields_valid(&props),
                "after-preimage code fields mismatch for {addr}: no observable \
                 code, but fields are neither all-zero nor deployed-empty: {:?}",
                account_props::CodeFields::of(&props));
        } else {
            let code = proven_db
                .code_by_hash_ref(observable)
                .unwrap_or_else(|e| panic!(
                    "post-state code {observable} for {addr} unavailable: {e}"
                ))
                .original_bytes();
            let code_version = (props.versioning >> 40) as u8;
            assert!(code_version <= 1,
                "unsupported code version {code_version} for {addr}");
            let ee_byte = (props.versioning >> 48) as u8;
            assert_eq!(ee_byte, account_props::EVM_EE_BYTE,
                "non-EVM execution environment {ee_byte} for {addr} is not \
                 supported by the second proof system");
            assert_eq!(
                account_props::CodeFields::of(&props),
                account_props::evm_code_fields(&code, code_version),
                "after-preimage code fields mismatch for {addr}"
            );
        }

        let flat_key = merkle::derive_account_properties_key(&(*addr).into_array());
        writes.insert(flat_key, merkle::AccountProperties::hash(after_preimage));
    }

    // Completeness. The loop above pins each *provided* after-preimage to REVM's
    // output, but nothing yet forces every account REVM actually changed to be
    // provided. If a changed account is omitted from both `after_preimages` and
    // `tree_update.entries`, its 0x8003 write never enters `writes`, the tree
    // keeps the stale pre-state leaf, and `state_after` silently drops the
    // debit/credit (omission attack, e.g. draining a victim without recording
    // the balance loss). Enumerate REVM's post-state and require every account
    // whose nonce or balance differs from its merkle-authenticated pre-state to
    // have an after-preimage.
    for (addr, db_account) in &cache_db.cache.accounts {
        if matches!(
            db_account.account_state,
            revm::database::AccountState::None | revm::database::AccountState::NotExisting
        ) {
            continue;
        }
        // Authenticated pre-state (ProvenDB is immutable; the mutations live in
        // the CacheDB overlay we are reading here). A same-tx create+destroy
        // ends at nonce 0 / balance 0 with no pre-state, so it registers as
        // unchanged and is correctly not required (mirrors evm.rs's EIP-6780
        // handling); a pre-existing selfdestruct zeroes the balance, which is a
        // real change and IS required.
        let (pre_nonce, pre_balance) = proven_db
            .basic_ref(*addr)
            .ok()
            .flatten()
            .map(|info| (info.nonce, info.balance))
            .unwrap_or((0, U256::ZERO));
        if db_account.info.nonce != pre_nonce || db_account.info.balance != pre_balance {
            assert!(
                after_map.contains_key(addr),
                "REVM changed account {addr} (nonce {pre_nonce}->{}, balance {pre_balance}->{}) \
                 but no after-preimage was provided: its 0x8003 write would be dropped \
                 from state_after",
                db_account.info.nonce,
                db_account.info.balance,
            );
        }
    }

    writes
}

/// Verify tree_update entries match computed writes.
/// Uses the set-theoretic identity: |A| == |B| ∧ A ⊆ B ⟹ A == B.
/// One length check + one forward pass — no reverse iteration needed.
pub(super) fn verify_tree_update(
    meta: &BatchMeta,
    revm_writes: &HashMap<B256, B256>,
) -> (B256, u64) {
    match meta.tree_update {
        Some(ref tree_update) => {
            // `apply` walks `operations.iter().zip(&entries)`, which stops at the
            // shorter vector. A truncated `operations` therefore silently drops
            // the trailing writes: the old root still matches the pinned value,
            // but `tree_root_after` and the leaf count are wrong. Require the two
            // vectors to have equal length so every entry gets an operation.
            assert_eq!(
                tree_update.operations.len(),
                tree_update.entries.len(),
                "tree_update length mismatch: {} operations, {} entries (a truncated \
                 operations vector drops trailing writes from the applied root)",
                tree_update.operations.len(),
                tree_update.entries.len(),
            );
            // The set-equality identity below (|A| == |B| ∧ A ⊆ B ⟹ A == B)
            // only holds when A (the entries' keys) is a genuine SET. `entries`
            // is a Vec with no uniqueness guarantee, so a duplicated key would
            // inflate `.len()` to match `revm_writes.len()` while the forward
            // pass silently drops a real write (the omitted key is never
            // examined). Reject duplicate keys first so the count check is a
            // true set-cardinality comparison.
            let distinct_keys: std::collections::HashSet<B256> =
                tree_update.entries.iter().map(|(k, _)| *k).collect();
            assert_eq!(
                distinct_keys.len(),
                tree_update.entries.len(),
                "tree_update.entries has duplicate keys ({} entries, {} distinct): \
                 duplicates defeat the write-set completeness check",
                tree_update.entries.len(),
                distinct_keys.len(),
            );
            if revm_writes.len() != tree_update.entries.len() {
                // Name the differing keys: a bare count is undebuggable.
                let tree_keys: std::collections::HashSet<_> =
                    tree_update.entries.iter().map(|(k, _)| *k).collect();
                let missing: Vec<_> = tree_keys
                    .iter()
                    .filter(|k| !revm_writes.contains_key(*k))
                    .collect();
                let extra: Vec<_> = revm_writes
                    .keys()
                    .filter(|k| !tree_keys.contains(*k))
                    .collect();
                panic!(
                    "write count mismatch: computed {} writes, tree_update has {};                      native-only keys: {missing:?}; guest-only keys: {extra:?}",
                    revm_writes.len(),
                    tree_update.entries.len(),
                );
            }
            for (key, tree_val) in &tree_update.entries {
                let computed_val = revm_writes.get(key).unwrap_or_else(||
                    panic!("tree_update has {key} not in computed writes"));
                assert_eq!(tree_val, computed_val,
                    "tree_update value mismatch for {key}: tree={tree_val}, computed={computed_val}");
            }
            // Bind the leaf count that drives `apply` to the count committed in
            // `state_before`. `apply` uses `tree_update.leaf_count_before` as the
            // insert start index and as the empty-subtree boundary, and it
            // returns this count as the committed `new_leaf_count`. The batch
            // also commits `meta.leaf_count_before` in `state_before`. Nothing
            // else ties the two. If they differ, an inflated count forges
            // `new_leaf_count`, and it forges `tree_root_after` on a batch that
            // inserts. The old-root check does not catch this: the phantom gap
            // holds only empty subtrees, so their empty-subtree anchors still
            // recover the pinned old root. Reject a count that does not match.
            assert_eq!(
                tree_update.leaf_count_before, meta.leaf_count_before,
                "tree_update.leaf_count_before ({}) must equal the committed state leaf count ({})",
                tree_update.leaf_count_before, meta.leaf_count_before
            );
            tree_update.apply(&meta.tree_root_before)
        }
        None => {
            assert!(revm_writes.is_empty(), "writes exist but no tree_update provided");
            (meta.tree_root_before, meta.leaf_count_before)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{BatchTreeUpdate, TreeLeaf, WriteOp};
    use crate::types::BatchMeta;

    /// Compress two child hashes, exactly like `merkle::blake2s_compress`
    /// (a single Blake2s over the two 32-byte slices).
    fn compress(lhs: &B256, rhs: &B256) -> B256 {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(lhs.as_slice());
        buf[32..].copy_from_slice(rhs.as_slice());
        merkle::blake2s(&buf)
    }

    /// Dense reference root over `leaves` (by index) for a tree of `leaf_count`
    /// leaves. Mirrors the private `merkle::tests::dense_root` oracle: hash every
    /// position up from the leaves and pad each level with empty subtrees.
    fn dense_root(leaves: &[(u64, TreeLeaf)], leaf_count: u64) -> B256 {
        let empty = merkle::empty_subtree_hashes_vec();
        let mut level: HashMap<u64, B256> = leaves
            .iter()
            .map(|(i, l)| (*i, merkle::hash_leaf(&l.key, &l.value, l.next_index)))
            .collect();
        let mut width = leaf_count;
        for depth in 0..merkle::TREE_DEPTH {
            let mut next: HashMap<u64, B256> = HashMap::new();
            let next_width = width.div_ceil(2);
            for i in 0..next_width {
                let l = level.get(&(2 * i)).copied().unwrap_or(empty[depth as usize]);
                let r = level.get(&(2 * i + 1)).copied().unwrap_or(empty[depth as usize]);
                next.insert(i, compress(&l, &r));
            }
            level = next;
            width = next_width;
        }
        level[&0]
    }

    /// A `BatchMeta` that carries the given root, committed leaf count, and
    /// tree update. Only these three fields drive `verify_tree_update`; the rest
    /// hold neutral values.
    fn meta_with(
        tree_root_before: B256,
        leaf_count_before: u64,
        tree_update: Option<BatchTreeUpdate>,
    ) -> BatchMeta {
        BatchMeta {
            tree_root_before,
            leaf_count_before,
            block_number_before: 0,
            last_block_timestamp_before: 0,
            block_hashes_blake_before: B256::ZERO,
            previous_block_hashes: vec![],
            upgrade_tx_hash: B256::ZERO,
            da_commitment_scheme: 2,
            pubdata: vec![],
            multichain_root: B256::ZERO,
            sl_chain_id: 0,
            blob_versioned_hashes: vec![],
            tree_update,
            account_preimages_after: vec![],
            fri_proof_verification_enabled: false,
            max_tx_gas_limit: 1 << 24,
            interop_proofs: None,
        }
    }

    /// Dense pre-state: MIN guard (idx 0), MAX guard (idx 1), one data leaf
    /// (idx 2). Returns (old_root, leaves-by-index). `leaf_count_before == 3`.
    fn build_three_leaf_tree(data_key: B256, data_value: B256) -> (B256, Vec<(u64, TreeLeaf)>) {
        let leaves = vec![
            (0u64, TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 }),
            (1u64, TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 }),
            (2u64, TreeLeaf { key: data_key, value: data_value, next_index: 1 }),
        ];
        (dense_root(&leaves, 3), leaves)
    }

    /// The inflation exploit is rejected: a `tree_update` whose
    /// `leaf_count_before` differs from the committed `meta.leaf_count_before`
    /// must panic before `apply`. Empty operations/entries and empty
    /// `revm_writes` pass every earlier check, so the run reaches the new
    /// binding assertion directly, with no tree fixture.
    #[test]
    #[should_panic(expected = "must equal the committed state leaf count")]
    fn rejects_leaf_count_mismatch() {
        let tree_update = BatchTreeUpdate {
            operations: vec![],
            entries: vec![],
            sorted_leaves: vec![],
            intermediate_hashes: vec![],
            // Inflated: the real committed count is 3.
            leaf_count_before: 3 + 7,
        };
        let meta = meta_with(B256::ZERO, 3, Some(tree_update));
        let revm_writes: HashMap<B256, B256> = HashMap::new();
        verify_tree_update(&meta, &revm_writes);
    }

    /// The happy path still works: with matching counts, a single-update
    /// `tree_update` passes `verify_tree_update` and returns the correct
    /// `(tree_root_after, new_leaf_count)`. The old-root check inside `apply`
    /// also guards the fixture — a wrong pre-state root would panic there.
    #[test]
    fn accepts_matching_leaf_count() {
        let data_key = B256::repeat_byte(0x20);
        let old_value = B256::repeat_byte(0xa1);
        let new_value = B256::repeat_byte(0xb2);

        let (old_root, mut leaves) = build_three_leaf_tree(data_key, old_value);

        // Independent reference for the post-state root: leaf 2 gets new_value.
        let mut after = leaves.clone();
        after[2].1.value = new_value;
        let expected_root_after = dense_root(&after, 3);

        let tree_update = BatchTreeUpdate {
            operations: vec![WriteOp::Update { index: 2 }],
            entries: vec![(data_key, new_value)],
            sorted_leaves: std::mem::take(&mut leaves),
            intermediate_hashes: vec![],
            leaf_count_before: 3,
        };
        let meta = meta_with(old_root, 3, Some(tree_update));
        let revm_writes: HashMap<B256, B256> = [(data_key, new_value)].into_iter().collect();

        let (root_after, new_leaf_count) = verify_tree_update(&meta, &revm_writes);
        assert_eq!(new_leaf_count, 3, "update-only batch keeps the leaf count");
        assert_eq!(root_after, expected_root_after, "post-state root must match the dense reference");
    }
}
