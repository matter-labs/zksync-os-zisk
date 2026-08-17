//! Proof-verified state database.
//!
//! Every storage and account read is verified against a merkle proof that
//! recovers the expected state root. Values come FROM the proofs, not from
//! a separate data path.

use std::collections::HashMap;

use revm::database_interface::DBErrorMarker;
use revm::primitives::{Address, B256, Bytes, U256, KECCAK_EMPTY};
use revm::state::{AccountInfo, Bytecode};
use revm::DatabaseRef;

use crate::account_props::CodeFields;
use crate::merkle::{self, StorageProof};
use crate::types::*;

/// The merkle-authenticated pre-state of every account a batch names, in the two
/// shapes the executor consumes.
#[derive(Debug, PartialEq)]
pub(super) struct VerifiedAccounts {
    /// Nonce, balance and code hash, as REVM reads them. None = proven
    /// non-existent.
    infos: HashMap<Address, Option<AccountInfo>>,
    /// The code-derived fields of the account's 124-byte properties blob, which
    /// `AccountInfo` does not carry. An account whose leaf the pre-state does
    /// not hold has no entry.
    code_fields: HashMap<Address, CodeFields>,
}

/// Database that verifies every read against a merkle proof.
/// Values are taken FROM the proofs — there is no separate unverified data path.
/// Proof results are cached after first verification to avoid re-hashing.
pub(super) struct ProvenDB {
    /// Pre-verified storage values: flat_key -> value (None = proven non-existing).
    /// All proofs are verified at construction time; reads are pure lookups.
    /// This includes account-property entries at address 0x8003.
    pub(super) verified_storage: HashMap<B256, Option<B256>>,
    /// Merkle-verified account pre-state. Every entry was proven against the
    /// tree root at construction time.
    verified_accounts: VerifiedAccounts,
    /// Verified bytecodes keyed by hash (keccak256 or blake2s).
    bytecodes: HashMap<B256, Bytecode>,
    /// Block hashes for BLOCKHASH opcode (verified against batch_meta).
    block_hashes: HashMap<u64, B256>,
}

impl ProvenDB {
    /// Assemble a `ProvenDB` from its already-verified component maps. Both the
    /// batch-collecting builder (`build_proven_db`) and the streaming builder
    /// (`super::stream`) funnel through here, so the two paths produce a
    /// byte-identical database.
    pub(super) fn from_parts(
        verified_storage: HashMap<B256, Option<B256>>,
        verified_accounts: VerifiedAccounts,
        bytecodes: HashMap<B256, Bytecode>,
        block_hashes: HashMap<u64, B256>,
    ) -> Self {
        ProvenDB {
            verified_storage,
            verified_accounts,
            bytecodes,
            block_hashes,
        }
    }

    /// Install the BLOCKHASH map once its pre-batch entries have been
    /// authenticated. Construction leaves the map empty; the execution path
    /// seeds it after `verify_block_hashes_blake_before` pins the before-ring.
    pub(super) fn set_block_hashes(&mut self, block_hashes: HashMap<u64, B256>) {
        self.block_hashes = block_hashes;
    }

    /// Record an intra-batch block hash computed in-guest so a later block's
    /// BLOCKHASH read resolves to this authenticated value, never to a witness
    /// entry.
    pub(super) fn insert_block_hash(&mut self, number: u64, hash: B256) {
        self.block_hashes.insert(number, hash);
    }

    /// The code-derived fields of an account's merkle-authenticated pre-state
    /// properties blob. Native rewrites the whole blob on every account change
    /// and carries these fields through unchanged unless it writes the account's
    /// code, so they are the post-state fields of an account whose code the
    /// batch never wrote. An account the pre-state tree does not hold has none.
    pub(super) fn pre_state_code_fields(&self, address: &Address) -> CodeFields {
        self.verified_accounts
            .code_fields
            .get(address)
            .cloned()
            .unwrap_or_else(CodeFields::empty)
    }
}

#[cfg(test)]
impl ProvenDB {
    /// Borrow all four component maps for A/B equality checks between the
    /// collecting and streaming builders.
    #[allow(clippy::type_complexity)]
    pub(super) fn parts_for_test(
        &self,
    ) -> (
        &HashMap<B256, Option<B256>>,
        &VerifiedAccounts,
        &HashMap<B256, Bytecode>,
        &HashMap<u64, B256>,
    ) {
        (
            &self.verified_storage,
            &self.verified_accounts,
            &self.bytecodes,
            &self.block_hashes,
        )
    }
}

#[derive(Debug)]
pub(super) struct ProvenDBError(String);

impl core::fmt::Display for ProvenDBError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProvenDB error: {}", self.0)
    }
}

impl std::error::Error for ProvenDBError {}
impl DBErrorMarker for ProvenDBError {}

impl DatabaseRef for ProvenDB {
    type Error = ProvenDBError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // Fast path: account was pre-verified from account_preimages
        if let Some(proven) = self.verified_accounts.infos.get(&address) {
            return Ok(proven.clone());
        }

        // Slow path: check verified_storage for account-property proof.
        // The server may include a proof without a preimage (for non-existent accounts).
        let addr_bytes: [u8; 20] = address.into_array();
        let flat_key = merkle::derive_account_properties_key(&addr_bytes);
        match self.verified_storage.get(&flat_key) {
            Some(None) => Ok(None), // proven non-existent
            Some(Some(_)) => Err(ProvenDBError(format!(
                "account {address} exists in merkle tree but no preimage in account_preimages"
            ))),
            None => Err(ProvenDBError(format!(
                "no proof for account {address}. The server must provide a merkle proof \
                 (existence or non-existence) for every account REVM accesses."
            ))),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash.is_zero() || code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        self.bytecodes.get(&code_hash).cloned().ok_or_else(|| {
            ProvenDBError(format!(
                "no bytecode for code_hash {code_hash}. The server must include \
                 all contract bytecodes in the batch."
            ))
        })
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let addr_bytes: [u8; 20] = address.into_array();
        let slot = B256::from(index.to_be_bytes::<32>());
        let flat_key = merkle::derive_flat_storage_key(&addr_bytes, &slot);

        match self.verified_storage.get(&flat_key) {
            Some(value) => Ok(value.map(|v| U256::from_be_bytes(v.0)).unwrap_or_default()),
            None => Err(ProvenDBError(format!(
                "no merkle proof for storage read: address={address}, slot={index}, flat_key={flat_key}"
            ))),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(self
            .block_hashes
            .get(&number)
            .copied()
            .unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Shared construction helpers.
//
// The verified-account, bytecode, block-hash, and per-proof verification logic
// is factored out so the batch-collecting `build_proven_db` and the streaming
// builder (`super::stream`, the streaming path) share EXACTLY the same code. Only *how the
// storage proofs are fed in* differs between the two paths (all-resident vs.
// verify-and-drop); everything downstream is identical, which is what makes the
// two paths produce a byte-identical `ProvenDB`.
// ---------------------------------------------------------------------------

/// The pre-state tree root every storage/account read proof in a block must
/// recover.
///
/// SOUNDNESS: this is ALWAYS the single L1-pinned batch pre-state root
/// `meta.tree_root_before`, NEVER the witness scalar `block.expected_tree_root`.
/// `tree_root_before` is chained to the previous batch's `state_after` on L1, so
/// it is the only pre-state root the guest trusts. Authenticating reads against a
/// witness-chosen per-block root would let an operator serve arbitrary pre-state
/// values (a forged owner, an inflated balance) from a fabricated tree, drive a
/// privileged read path, and fold the resulting writes into a `tree_root_after`
/// native never produces — a read-authentication bypass the batch-level tree
/// update (anchored to the real `tree_root_before`, binding only WRITTEN values)
/// does not catch.
///
/// Multi-block batches stay sound without per-block read roots: intra-batch
/// writes are served from the in-guest CacheDB overlay (see
/// `run_execution_and_commit`), so a later block that reads a key an earlier
/// block wrote gets the overlay value, and a later block that reads an untouched
/// key gets its pre-batch value — whose proof against `tree_root_before` is
/// valid. `block.expected_tree_root` is retained on the wire (version
/// compatibility) but is no longer trusted here; `validate_expected_tree_roots`
/// asserts up front that it is zero or equal to `tree_root_before`.
pub(super) fn expected_root_for_block<'a>(
    _block: &'a BlockInput,
    meta: &'a BatchMeta,
) -> &'a B256 {
    &meta.tree_root_before
}

/// Verify one storage proof, returning the recovered root and the proven value
/// (`None` = proven non-existent). Panics with the original message on a
/// malformed proof — identical to the inline check in the pre-refactor code.
pub(super) fn verify_storage_proof(key: &B256, proof: &StorageProof) -> (B256, Option<B256>) {
    proof
        .verify(key)
        .unwrap_or_else(|e| panic!("merkle proof failed for key {key}: {e}"))
}

/// Load batch-level bytecodes. All are keyed by keccak256(code). The server
/// converts blake2s-keyed force-deploy bytecodes to keccak256 at
/// witness-building time.
pub(super) fn load_bytecodes(bytecodes: &[(B256, Vec<u8>)]) -> HashMap<B256, Bytecode> {
    let mut out: HashMap<B256, Bytecode> = HashMap::new();
    for (hash, code) in bytecodes {
        let computed = crate::hash::keccak256(code);
        assert_eq!(
            computed, *hash,
            "bytecode hash mismatch: key={hash}, keccak256={computed}, len={}",
            code.len()
        );
        out.insert(*hash, Bytecode::new_raw(Bytes::copy_from_slice(code)));
    }
    out
}

/// Build the verified-account map from the blocks' account preimages, resolving
/// each against the already-verified storage values and bytecodes. First block
/// to name an account wins (matching the pre-refactor loop).
pub(super) fn build_verified_accounts(
    blocks: &[BlockInput],
    verified_storage: &HashMap<B256, Option<B256>>,
    bytecodes: &HashMap<B256, Bytecode>,
) -> VerifiedAccounts {
    let mut infos: HashMap<Address, Option<AccountInfo>> = HashMap::new();
    let mut code_fields: HashMap<Address, CodeFields> = HashMap::new();

    for block in blocks {
        for (addr, preimage) in &block.account_preimages {
            if infos.contains_key(addr) {
                continue;
            }
            let addr_bytes: [u8; 20] = addr.into_array();
            let flat_key = merkle::derive_account_properties_key(&addr_bytes);

            let proven_value = verified_storage.get(&flat_key).unwrap_or_else(|| {
                panic!("account_preimage for {addr} but no storage proof at flat_key={flat_key}")
            });

            match proven_value {
                None => {
                    infos.insert(*addr, None);
                }
                Some(proven_hash) => {
                    let preimage_hash = merkle::AccountProperties::hash(preimage);
                    assert_eq!(
                        *proven_hash, preimage_hash,
                        "account preimage hash mismatch for {addr}: \
                         proven={proven_hash}, computed={preimage_hash}"
                    );

                    // In-guest rejection: a preimage whose length is not the
                    // 124-byte account-properties layout is invalid witness
                    // data and must fail the proof.
                    let props = merkle::AccountProperties::decode(preimage)
                        .expect("account preimage must decode as account properties");
                    let code_hash = if props.observable_bytecode_hash.is_zero() {
                        if props.nonce == 0 && props.balance == [0u8; 32] {
                            B256::ZERO
                        } else {
                            KECCAK_EMPTY
                        }
                    } else {
                        props.observable_bytecode_hash
                    };
                    let code = bytecodes.get(&code_hash).cloned();

                    infos.insert(
                        *addr,
                        Some(AccountInfo {
                            nonce: props.nonce,
                            balance: U256::from_be_bytes(props.balance),
                            code_hash,
                            code,
                            account_id: None,
                        }),
                    );
                    code_fields.insert(*addr, CodeFields::of(&props));
                }
            }
        }
    }

    VerifiedAccounts { infos, code_fields }
}

/// Cross-check the witnessed per-block `block_hashes` against
/// `meta.previous_block_hashes`.
///
/// This is a witness-consistency guard only; it does NOT build the BLOCKHASH
/// map. The map the opcode reads is seeded in `run_execution_and_commit` from
/// authenticated data alone — the L1-pinned before-ring for pre-batch numbers
/// and the guest's own computed header hashes for intra-batch numbers (see
/// `pre_batch_block_hashes`). A raw witness `block_hashes` entry never feeds the
/// map, so a later block cannot inject a forged historical hash.
///
/// `previous_block_hashes` is the 255-entry ring preceding the LAST block of the
/// batch. Index `j` holds the hash of block `last_block - 255 + j`. The last
/// block's number is used (not `block_number_before`), so multi-block batches
/// index into the ring correctly.
pub(super) fn verify_witness_block_hashes(blocks: &[BlockInput], meta: &BatchMeta) {
    let Some(last_block) = blocks.last() else { return };
    let last_num = last_block.number;
    if last_num < 255 {
        return;
    }
    let oldest_available = last_num - 255;
    for block in blocks {
        for &(num, hash) in &block.block_hashes {
            if num >= oldest_available && num < last_num {
                let idx = (num - oldest_available) as usize;
                if idx < meta.previous_block_hashes.len() {
                    let verified_hash = meta.previous_block_hashes[idx];
                    if !verified_hash.is_zero() {
                        assert_eq!(
                            hash, verified_hash,
                            "block hash mismatch for block {num}: input={hash}, verified={verified_hash}"
                        );
                    }
                }
            }
        }
    }
}

/// Seed the BLOCKHASH map with the AUTHENTICATED pre-batch block hashes.
///
/// The map serves the BLOCKHASH opcode via `ProvenDB::block_hash_ref`. Each
/// pre-batch slot is taken from `before_ring`, the 256-entry ring the caller has
/// already authenticated against the L1-pinned `block_hashes_blake_before`. Ring
/// index `i` holds the hash of block `first_block_number - 256 + i` (oldest at
/// 0, the first block's parent at 255). Every pre-batch block a batch member can
/// reference with BLOCKHASH falls inside this window, so the ring covers them
/// all. Intra-batch numbers are added later from the guest's own computed header
/// hashes.
pub(super) fn pre_batch_block_hashes(
    before_ring: &[B256; 256],
    first_block_number: u64,
) -> HashMap<u64, B256> {
    let mut block_hashes: HashMap<u64, B256> = HashMap::new();
    for (i, hash) in before_ring.iter().enumerate() {
        let num = first_block_number as i128 - 256 + i as i128;
        if num >= 0 && !hash.is_zero() {
            block_hashes.insert(num as u64, *hash);
        }
    }
    block_hashes
}

/// Build a ProvenDB for the entire batch (batch-collecting path).
///
/// All merkle proofs from all blocks are verified at construction time and
/// their values are stored in flat maps. Each block's proofs are verified
/// against that block's expected tree root. This path holds every proof (and
/// therefore every merkle sibling) resident at once; the streaming path in
/// `super::stream` (the streaming path) verifies and drops each proof instead, but reuses
/// the same helpers below so the resulting `ProvenDB` is byte-identical.
pub(super) fn build_proven_db(input: &BatchInput) -> ProvenDB {
    let meta = &input.batch_meta;

    let bytecodes = load_bytecodes(&input.bytecodes);

    let mut verified_storage: HashMap<B256, Option<B256>> = HashMap::new();
    for block in &input.blocks {
        let expected_root = expected_root_for_block(block, meta);

        // Verify all merkle proofs and extract values FROM the proofs.
        for (key, proof) in &block.storage_proofs {
            let (root, value) = verify_storage_proof(key, proof);
            assert_eq!(
                root, *expected_root,
                "proof for {key} recovers root {root}, expected {expected_root}"
            );

            // First block's proof wins — later blocks may have the same key
            // against a different root (after writes), but the pre-state value
            // is what matters for the ProvenDB. Intra-batch updates go through CacheDB.
            verified_storage.entry(*key).or_insert(value);
        }
    }

    let verified_accounts = build_verified_accounts(&input.blocks, &verified_storage, &bytecodes);
    // The BLOCKHASH map is seeded from authenticated data during execution, not
    // from the witness; construction leaves it empty and only runs the
    // witness-consistency cross-check.
    verify_witness_block_hashes(&input.blocks, meta);

    ProvenDB::from_parts(verified_storage, verified_accounts, bytecodes, HashMap::new())
}
