//! Post-execution verification.
//!
//! Builds the complete write map (storage + 0x8003 account properties) from
//! REVM's CacheDB and verifies it against the tree_update merkle proof.

use std::collections::{HashMap, HashSet};

use revm::database::{AccountState, CacheDB, DbAccount};
use revm::state::AccountInfo;
use revm::DatabaseRef;
use revm::primitives::{Address, B256, KECCAK_EMPTY, U256};

use crate::account_props;
use crate::merkle;
use crate::types::*;
use super::proven_db::ProvenDB;

/// What execution left behind for an account in REVM's cache.
enum PostState<'a> {
    /// Execution wrote the account; this is its post-state.
    Written(&'a AccountInfo),
    /// EIP-6780 destruction removed the account. Native keeps the leaf and
    /// zeroes it, so the post-state is the zeroed account encoding.
    Destroyed,
    /// Execution never wrote the account.
    Unwritten,
}

/// Classify what execution left for one account.
///
/// `CacheDB` records `AccountState::NotExisting` for two unrelated events: a
/// read of an absent account (`DbAccount::new_not_existing`) and a destruction
/// (`CacheDB::commit` clears the entry). Both leave an identical entry — default
/// `info`, empty storage — so a destruction is recognised from `destroyed`, the
/// set the execution journal reports, and never from the cache entry alone.
fn post_state(account: Option<&DbAccount>, destroyed: bool) -> PostState<'_> {
    match account {
        Some(account) => match account.account_state {
            AccountState::Touched | AccountState::StorageCleared => {
                PostState::Written(&account.info)
            }
            AccountState::NotExisting if destroyed => PostState::Destroyed,
            AccountState::NotExisting | AccountState::None => PostState::Unwritten,
        },
        // An absent cache entry is no evidence either way, so the destruction
        // set decides alone: a destroyed account holds its zeroed post-state
        // whether or not the cache kept an entry for it.
        None if destroyed => PostState::Destroyed,
        None => PostState::Unwritten,
    }
}

/// The code fields native writes for an account execution wrote.
///
/// Native derives every code field from the code the account holds, and it
/// carries the fields through unchanged on a change that does not write code.
/// The code REVM left therefore fixes the fields, and the operator chooses
/// none of them:
///
/// - an account that holds observable code carries the derivation of exactly
///   that code, so a preimage cannot bind one account's code to another;
/// - a deployment that completed in this batch carries the deployed encoding,
///   empty runtime code included (native `deploy_code` runs for every completed
///   deployment);
/// - an account whose code the batch cleared carries the zeroed encoding, which
///   is what native `set_delegation` writes when it clears a delegation;
/// - an account whose code the batch never wrote keeps the code fields of its
///   merkle-authenticated pre-state.
fn expected_code_fields(
    proven_db: &ProvenDB,
    addr: &Address,
    code_hash: B256,
    deployed_in_batch: bool,
) -> account_props::CodeFields {
    // REVM reports `KECCAK_EMPTY` for an account that holds no code, and its
    // own `AccountInfo::is_empty` reads the zero hash the same way, so both
    // values mean "no code" here. Native carries a third value for the same
    // situation: the never-deployed encoding leaves the observable hash zero
    // while the deployed-with-empty-code encoding holds `keccak256("")`, and
    // the branches below decide which of the two this account is in.
    if code_hash == KECCAK_EMPTY || code_hash.is_zero() {
        if deployed_in_batch {
            return account_props::evm_code_fields(&[]);
        }
        let pre_state = proven_db.pre_state_code_fields(addr);
        return if pre_state.observable_bytecode_len == 0 {
            pre_state
        } else {
            account_props::CodeFields::empty()
        };
    }
    // `load_bytecodes` keys this map by keccak256 of the code it holds, so the
    // lookup returns the code REVM left and nothing else.
    let code = proven_db
        .code_by_hash_ref(code_hash)
        .unwrap_or_else(|e| panic!("post-state code {code_hash} for {addr} unavailable: {e}"))
        .original_bytes();
    account_props::evm_code_fields(&code)
}

/// Build the complete write map: flat_key → new_value for both regular storage
/// writes and 0x8003 account-property writes. For 0x8003, the server provides
/// after-state preimages; we verify nonce/balance match REVM output, then use
/// blake2s(preimage) as the value.
pub(super) fn build_revm_write_map(
    storage_writes: &HashMap<(Address, U256), U256>,
    destroyed_accounts: &HashSet<Address>,
    deployed_accounts: &HashSet<Address>,
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
        // In-guest rejection: an after-preimage that is not the 124-byte
        // account-properties layout is invalid witness data.
        let props = merkle::AccountProperties::decode(after_preimage)
            .expect("after-preimage must decode as account properties");

        let post = post_state(
            cache_db.cache.accounts.get(addr),
            destroyed_accounts.contains(addr),
        );

        // Injection guard. An after-preimage for an account REVM never executed
        // is unconstrained by the post-state pin below, so accepting it lets
        // an operator fabricate an account-property write (e.g. mint a balance
        // onto a dormant EOA). The only legitimate non-executed write is the
        // system force-deploy path, which is confined to upgrade batches (the
        // documented trusted hole). Outside an upgrade batch, reject it.
        assert!(
            !matches!(post, PostState::Unwritten) || is_upgrade_batch,
            "after-preimage for non-executed account {addr} outside an upgrade batch: \
             account-property writes must correspond to accounts changed by execution"
        );

        match post {
            PostState::Written(info) => {
                assert_eq!(props.nonce, info.nonce,
                    "after-preimage nonce mismatch for {addr}: preimage={}, revm={}",
                    props.nonce, info.nonce);
                assert_eq!(U256::from_be_bytes(props.balance), info.balance,
                    "after-preimage balance mismatch for {addr}");
                // Every code field is derived, so the account has one legal
                // leaf and the preimage carries no operator choice at all.
                assert_eq!(
                    account_props::CodeFields::of(&props),
                    expected_code_fields(
                        proven_db,
                        addr,
                        info.code_hash,
                        deployed_accounts.contains(addr),
                    ),
                    "after-preimage code fields mismatch for {addr}"
                );
            }
            // A destroyed account has exactly one legal post-state, so the
            // preimage is pinned whole rather than field by field: any other
            // content leaves value alive in an account execution emptied.
            PostState::Destroyed => assert!(
                account_props::is_zeroed_account(&props),
                "after-preimage for destroyed account {addr} is not the zeroed \
                 account leaf: destruction writes nonce 0, balance 0, and no code"
            ),
            // A system force-deploy changes an account REVM never executed, so
            // there is no post-state to derive the fields from. It is the
            // documented trusted hole of an upgrade batch: the fields rest on
            // the tree authentication plus their own self-consistency.
            PostState::Unwritten => {
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
                    let ee_byte = (props.versioning >> 48) as u8;
                    assert_eq!(ee_byte, account_props::EVM_EE_BYTE,
                        "non-EVM execution environment {ee_byte} for {addr} is not \
                         supported by the second proof system");
                    assert_eq!(
                        account_props::CodeFields::of(&props),
                        account_props::evm_code_fields(&code),
                        "after-preimage code fields mismatch for {addr}"
                    );
                }
            }
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
        // Destruction empties the account, so it enters this comparison with a
        // zeroed post-state: a destroyed account that held a balance changed,
        // and dropping its write would leave that balance alive in the tree
        // while the beneficiary keeps the credit.
        let (post_nonce, post_balance) =
            match post_state(Some(db_account), destroyed_accounts.contains(addr)) {
                PostState::Written(info) => (info.nonce, info.balance),
                PostState::Destroyed => (0, U256::ZERO),
                PostState::Unwritten => continue,
            };
        // Authenticated pre-state (ProvenDB is immutable; the mutations live in
        // the CacheDB overlay we are reading here).
        let (pre_nonce, pre_balance) = proven_db
            .basic_ref(*addr)
            .ok()
            .flatten()
            .map(|info| (info.nonce, info.balance))
            .unwrap_or((0, U256::ZERO));
        if post_nonce != pre_nonce || post_balance != pre_balance {
            assert!(
                after_map.contains_key(addr),
                "REVM changed account {addr} (nonce {pre_nonce}->{post_nonce}, \
                 balance {pre_balance}->{post_balance}) but no after-preimage was \
                 provided: its 0x8003 write would be dropped from state_after",
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
    use revm::primitives::Bytes;
    use revm::state::Bytecode;

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

    /// The 124-byte account-properties blob native writes for an account with
    /// no nonce, no balance and no code.
    fn zeroed_account_blob() -> Vec<u8> {
        vec![0u8; merkle::AccountProperties::ENCODED_SIZE]
    }

    /// A `CacheDB` whose merkle-authenticated pre-state holds the given
    /// account-properties blobs, whose cache holds `cache_entries`, and whose
    /// code map holds `bytecodes`.
    ///
    /// The blobs resolve through the production helper
    /// `build_verified_accounts`, so a test reads the same `AccountInfo` and the
    /// same pre-state code fields the guest derives from an authenticated
    /// preimage. `build_revm_write_map` reads nothing else from the database.
    fn cache_db_with(
        pre_state: Vec<(Address, Vec<u8>)>,
        cache_entries: Vec<(Address, DbAccount)>,
        bytecodes: HashMap<B256, Bytecode>,
    ) -> CacheDB<ProvenDB> {
        let verified_storage: HashMap<B256, Option<B256>> = pre_state
            .iter()
            .map(|(addr, blob)| {
                (
                    merkle::derive_account_properties_key(&addr.into_array()),
                    Some(merkle::AccountProperties::hash(blob)),
                )
            })
            .collect();
        let block = BlockInput {
            number: 1,
            timestamp: 0,
            base_fee: 0,
            gas_limit: 0,
            coinbase: Address::ZERO,
            prev_randao: B256::ZERO,
            transactions: vec![],
            account_preimages: pre_state,
            block_hashes: vec![],
            storage_proofs: vec![],
            block_header_hash: B256::ZERO,
            l2_to_l1_logs: vec![],
            expected_tree_root: B256::ZERO,
        };
        let verified_accounts = crate::executor::proven_db::build_verified_accounts(
            std::slice::from_ref(&block),
            &verified_storage,
            &bytecodes,
        );
        let proven_db =
            ProvenDB::from_parts(verified_storage, verified_accounts, bytecodes, HashMap::new());
        let mut cache_db = CacheDB::new(proven_db);
        cache_db.cache.accounts.extend(cache_entries);
        cache_db
    }

    /// The code map keyed the way `load_bytecodes` keys it: keccak256 of the
    /// raw code, which is what an after-preimage's `observable_bytecode_hash`
    /// resolves against.
    fn bytecode_map(codes: &[&[u8]]) -> HashMap<B256, Bytecode> {
        codes
            .iter()
            .map(|code| {
                (
                    crate::hash::keccak256(code),
                    Bytecode::new_raw(Bytes::copy_from_slice(code)),
                )
            })
            .collect()
    }

    /// The 124-byte account-properties blob carrying `fields`, `nonce` and
    /// `balance`, at the offsets `merkle::AccountProperties::decode` reads.
    fn account_blob(
        fields: &account_props::CodeFields,
        nonce: u64,
        balance: U256,
    ) -> Vec<u8> {
        let mut blob = vec![0u8; merkle::AccountProperties::ENCODED_SIZE];
        blob[0..8].copy_from_slice(&fields.versioning.to_be_bytes());
        blob[8..16].copy_from_slice(&nonce.to_be_bytes());
        blob[16..48].copy_from_slice(&balance.to_be_bytes::<32>());
        blob[48..80].copy_from_slice(fields.bytecode_hash.as_slice());
        blob[80..84].copy_from_slice(&fields.unpadded_code_len.to_be_bytes());
        blob[84..88].copy_from_slice(&fields.artifacts_len.to_be_bytes());
        blob[88..120].copy_from_slice(fields.observable_bytecode_hash.as_slice());
        blob[120..124].copy_from_slice(&fields.observable_bytecode_len.to_be_bytes());
        blob
    }

    /// The cache entry execution leaves for an account it wrote without code,
    /// carrying the post-state nonce and balance the after-preimage must match.
    /// `AccountInfo::default` carries `KECCAK_EMPTY`, which is what REVM reports
    /// for an account that holds no code.
    fn written(nonce: u64, balance: U256) -> DbAccount {
        DbAccount {
            info: AccountInfo { nonce, balance, ..Default::default() },
            account_state: AccountState::Touched,
            ..Default::default()
        }
    }

    /// The cache entry execution leaves for an account it wrote that holds
    /// `code`, carrying the post-state code hash the after-preimage must match.
    fn written_holding(nonce: u64, balance: U256, code: &[u8]) -> DbAccount {
        DbAccount {
            info: AccountInfo {
                nonce,
                balance,
                code_hash: crate::hash::keccak256(code),
                ..Default::default()
            },
            account_state: AccountState::Touched,
            ..Default::default()
        }
    }

    /// An account created and destroyed inside one transaction reaches
    /// verification as a cleared cache entry, and native still writes its zeroed
    /// leaf. The zeroed after-preimage must therefore be accepted and become the
    /// account's 0x8003 write — the case the destruction set exists for.
    #[test]
    fn accepts_zeroed_preimage_for_destroyed_account() {
        let addr = Address::repeat_byte(0x11);
        // Pre-state balance 1: the destruction is a real change, so the
        // completeness pass also requires this after-preimage.
        let pre = account_blob(&account_props::CodeFields::empty(), 0, U256::from(1));
        let cache_db = cache_db_with(
            vec![(addr, pre)],
            vec![(addr, DbAccount::new_not_existing())],
            HashMap::new(),
        );

        let writes = build_revm_write_map(
            &HashMap::new(),
            &HashSet::from([addr]),
            &HashSet::new(),
            &cache_db,
            &[(addr, zeroed_account_blob())],
            false,
        );

        let key = merkle::derive_account_properties_key(&addr.into_array());
        assert_eq!(
            writes,
            HashMap::from([(key, merkle::AccountProperties::hash(&zeroed_account_blob()))]),
            "the destroyed account's zeroed leaf must be the batch's only 0x8003 write"
        );
    }

    /// Destruction decides the post-state even when the cache holds no entry
    /// for the account at all. The zeroed leaf must still become the account's
    /// write: routing an absent entry to `Unwritten` would drop the content
    /// pin inside an upgrade batch, and would trip the injection guard outside
    /// one.
    #[test]
    fn accepts_zeroed_preimage_for_destroyed_account_absent_from_the_cache() {
        let addr = Address::repeat_byte(0x44);
        let pre = account_blob(&account_props::CodeFields::empty(), 0, U256::from(1));
        let cache_db = cache_db_with(vec![(addr, pre)], vec![], HashMap::new());

        let writes = build_revm_write_map(
            &HashMap::new(),
            &HashSet::from([addr]),
            &HashSet::new(),
            &cache_db,
            &[(addr, zeroed_account_blob())],
            false,
        );

        let key = merkle::derive_account_properties_key(&addr.into_array());
        assert_eq!(
            writes,
            HashMap::from([(key, merkle::AccountProperties::hash(&zeroed_account_blob()))]),
            "the destroyed account's zeroed leaf must be the batch's only 0x8003 write"
        );
    }

    /// The injection guard stays closed for an account execution never wrote:
    /// its after-preimage is pinned by nothing, so accepting it would let an
    /// operator write arbitrary properties onto a dormant account.
    #[test]
    #[should_panic(expected = "after-preimage for non-executed account")]
    fn rejects_preimage_for_untouched_account() {
        let addr = Address::repeat_byte(0x22);
        let read_only = DbAccount {
            info: AccountInfo { balance: U256::from(5), ..Default::default() },
            account_state: AccountState::None,
            ..Default::default()
        };
        let cache_db = cache_db_with(vec![], vec![(addr, read_only)], HashMap::new());

        build_revm_write_map(
            &HashMap::new(),
            &HashSet::new(),
            &HashSet::new(),
            &cache_db,
            &[(addr, zeroed_account_blob())],
            false,
        );
    }

    /// Admitting destroyed accounts must not admit their CONTENT: a destroyed
    /// account has one legal post-state, so a preimage that keeps a balance
    /// alive in it is rejected.
    #[test]
    #[should_panic(expected = "is not the zeroed account leaf")]
    fn rejects_non_zeroed_preimage_for_destroyed_account() {
        let addr = Address::repeat_byte(0x33);
        let cache_db =
            cache_db_with(vec![], vec![(addr, DbAccount::new_not_existing())], HashMap::new());

        let mut blob = zeroed_account_blob();
        blob[47] = 1; // balance = 1 wei

        build_revm_write_map(
            &HashMap::new(),
            &HashSet::from([addr]),
            &HashSet::new(),
            &cache_db,
            &[(addr, blob)],
            false,
        );
    }

    /// The code version is not the operator's to choose. Native stores code
    /// only under the artifact-caching version, so the pre-artifact-caching
    /// encoding of the same code must be rejected: accepting it would give one
    /// account holding one code two legal leaves, and the batch two legal
    /// post-state roots.
    #[test]
    #[should_panic(expected = "after-preimage code fields mismatch")]
    fn rejects_after_preimage_claiming_a_non_native_code_version() {
        let addr = Address::repeat_byte(0x44);
        // Eight bytes, so the code needs no alignment padding and the
        // pre-artifact-caching preimage is the code alone.
        let code: [u8; 8] = [0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        // The leaf a pre-artifact-caching encoding of this code would produce:
        // code version 0, no jumpdest bitmap, and a hash over the bare code.
        let mut fields = account_props::evm_code_fields(&code);
        fields.versioning = 0x0101_0000_0000_0000;
        fields.artifacts_len = 0;
        fields.bytecode_hash = merkle::blake2s(&code);

        // REVM left this exact code on the account, so the claimed code version
        // is the only thing the preimage gets wrong.
        let cache_db = cache_db_with(
            vec![],
            vec![(addr, written_holding(1, U256::ZERO, &code))],
            bytecode_map(&[&code]),
        );

        build_revm_write_map(
            &HashMap::new(),
            &HashSet::new(),
            &HashSet::new(),
            &cache_db,
            &[(addr, account_blob(&fields, 1, U256::ZERO))],
            false,
        );
    }

    /// An after-preimage may not bind code to an account REVM left without any.
    /// The code map proves only that a blob hashes to the hash it is filed
    /// under, so nothing but this pin ties the hash to the account: an operator
    /// could otherwise hand any account the batch touched the code of any
    /// contract the batch carries, and with it that contract's storage.
    #[test]
    #[should_panic(expected = "after-preimage code fields mismatch")]
    fn rejects_after_preimage_binding_another_contracts_code() {
        let plain_account = Address::repeat_byte(0x61);
        let runtime_code: [u8; 5] = [0x5b, 0x60, 0x01, 0x00, 0x5b];

        // Execution moved the balance and left the account holding no code.
        let cache_db = cache_db_with(
            vec![(
                plain_account,
                account_blob(&account_props::CodeFields::empty(), 0, U256::from(1)),
            )],
            vec![(plain_account, written(0, U256::from(2)))],
            bytecode_map(&[&runtime_code]),
        );

        build_revm_write_map(
            &HashMap::new(),
            &HashSet::new(),
            &HashSet::new(),
            &cache_db,
            &[(
                plain_account,
                account_blob(&account_props::evm_code_fields(&runtime_code), 0, U256::from(2)),
            )],
            false,
        );
    }

    /// An account with no code that no deployment reached keeps the code fields
    /// of its authenticated pre-state. A never-deployed account that claims the
    /// deployed-with-empty-code leaf must be rejected: accepting it would give
    /// the batch a second post-state root and the operator the choice between
    /// the two.
    #[test]
    #[should_panic(expected = "after-preimage code fields mismatch")]
    fn rejects_deployed_empty_leaf_for_a_never_deployed_account() {
        let never_deployed = Address::repeat_byte(0x62);
        let cache_db = cache_db_with(
            vec![(
                never_deployed,
                account_blob(&account_props::CodeFields::empty(), 0, U256::from(1)),
            )],
            vec![(never_deployed, written(0, U256::from(2)))],
            HashMap::new(),
        );

        build_revm_write_map(
            &HashMap::new(),
            &HashSet::new(),
            &HashSet::new(),
            &cache_db,
            &[(
                never_deployed,
                account_blob(&account_props::evm_code_fields(&[]), 0, U256::from(2)),
            )],
            false,
        );
    }

    /// The other direction of the same choice: an account native deployed with
    /// empty runtime code in an earlier batch keeps the deployed encoding while
    /// its balance moves, so the zeroed leaf must be rejected for it.
    #[test]
    #[should_panic(expected = "after-preimage code fields mismatch")]
    fn rejects_zeroed_leaf_for_an_account_deployed_with_empty_code() {
        let deployed_empty = Address::repeat_byte(0x63);
        let cache_db = cache_db_with(
            vec![(
                deployed_empty,
                account_blob(&account_props::evm_code_fields(&[]), 1, U256::from(1)),
            )],
            vec![(deployed_empty, written(1, U256::from(2)))],
            HashMap::new(),
        );

        build_revm_write_map(
            &HashMap::new(),
            &HashSet::new(),
            &HashSet::new(),
            &cache_db,
            &[(
                deployed_empty,
                account_blob(&account_props::CodeFields::empty(), 1, U256::from(2)),
            )],
            false,
        );
    }

    /// Every code-field shape native writes must still pass in one batch: a
    /// fresh deployment, an account that keeps its code while its balance
    /// moves, a plain account with no code at all, an EIP-7702 delegation set,
    /// a delegation cleared, and a deployment whose runtime code is empty.
    /// Deriving the fields must reject none of them.
    #[test]
    fn accepts_every_native_code_field_shape() {
        let runtime_code: [u8; 5] = [0x5b, 0x60, 0x01, 0x00, 0x5b];
        let mut designator = account_props::EIP7702_DELEGATION_MARKER.to_vec();
        designator.extend_from_slice(&[0x77; 20]);

        let deployed = Address::repeat_byte(0x51);
        let code_kept = Address::repeat_byte(0x52);
        let delegated = Address::repeat_byte(0x53);
        let delegation_cleared = Address::repeat_byte(0x54);
        let deployed_empty = Address::repeat_byte(0x55);
        let plain_account = Address::repeat_byte(0x56);

        let code_fields = account_props::evm_code_fields(&runtime_code);
        let delegation_fields = account_props::evm_code_fields(&designator);
        let no_code = account_props::CodeFields::empty();

        let after_preimages = vec![
            // Fresh deployment: no pre-state, nonce 1, the derived code fields.
            (deployed, account_blob(&code_fields, 1, U256::ZERO)),
            // Balance-only change: native rewrites the whole blob and preserves
            // the code fields the account already had.
            (code_kept, account_blob(&code_fields, 3, U256::from(2))),
            // Delegation set: delegated status, no artifacts.
            (delegated, account_blob(&delegation_fields, 1, U256::from(5))),
            // Delegation cleared: native zeroes every code field.
            (delegation_cleared, account_blob(&no_code, 2, U256::ZERO)),
            // Deployment with empty runtime code: the empty-blob hashes.
            (deployed_empty, account_blob(&account_props::evm_code_fields(&[]), 1, U256::ZERO)),
            // Balance-only change on an account that never held code.
            (plain_account, account_blob(&no_code, 0, U256::from(9))),
        ];

        // Authenticated pre-state: the account that keeps its code already held
        // it, the account whose delegation is cleared already held the
        // designator, and the delegation target starts with no code.
        let cache_db = cache_db_with(
            vec![
                (code_kept, account_blob(&code_fields, 3, U256::from(1))),
                (delegated, account_blob(&no_code, 0, U256::from(5))),
                (delegation_cleared, account_blob(&delegation_fields, 1, U256::ZERO)),
                (plain_account, account_blob(&no_code, 0, U256::from(4))),
            ],
            vec![
                (deployed, written_holding(1, U256::ZERO, &runtime_code)),
                (code_kept, written_holding(3, U256::from(2), &runtime_code)),
                (delegated, written_holding(1, U256::from(5), &designator)),
                (delegation_cleared, written(2, U256::ZERO)),
                (deployed_empty, written(1, U256::ZERO)),
                (plain_account, written(0, U256::from(9))),
            ],
            bytecode_map(&[&runtime_code, &designator]),
        );

        let writes = build_revm_write_map(
            &HashMap::new(),
            &HashSet::new(),
            // Both deployments completed in this batch, the empty-runtime-code
            // one included.
            &HashSet::from([deployed, deployed_empty]),
            &cache_db,
            &after_preimages,
            false,
        );

        let expected: HashMap<B256, B256> = after_preimages
            .iter()
            .map(|(addr, blob)| {
                (
                    merkle::derive_account_properties_key(&addr.into_array()),
                    merkle::AccountProperties::hash(blob),
                )
            })
            .collect();
        assert_eq!(
            writes, expected,
            "every native code-field shape must become its 0x8003 write"
        );
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
