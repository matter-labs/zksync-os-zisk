//! Streaming deserialization of the storage-proof witness.
//!
//! The read-spam OOM is floored by `bincode::deserialize::<BatchInput>`: it
//! materialises every `StorageProof.siblings` (≈ `32·depth` bytes per slot,
//! up to ~284k slots) on the heap *before* proof verification even begins.
//! Freeing the siblings afterwards cannot help — the peak is already reached
//! at deserialize time.
//!
//! This module parses the *same* bincode wire format, but drives it with a
//! `DeserializeSeed` tower that consumes the `blocks[].storage_proofs` sequence
//! element-by-element: each `(key, StorageProof)` is deserialized, verified
//! against the block's pre-state root, its value extracted into the
//! `verified_storage` map, and then DROPPED before the next proof is read. The
//! merkle siblings are therefore never all resident at once — the resident set
//! holds only the small verified value map (`~65 B/slot`), independent of tree
//! depth.
//!
//! Everything else (`version`, scalars, `transactions`, `account_preimages`,
//! `block_hashes`, `batch_meta`, `bytecodes`) deserializes through the normal
//! derived `Deserialize` impls — those are not the dominant memory term. The
//! reconstructed `BatchInput` carries EMPTY `storage_proofs` vectors (they are
//! consumed only here and never read during execution/commitment), and the
//! `ProvenDB` is assembled with the exact same helpers the collecting path
//! (`proven_db::build_proven_db`) uses, so both paths are byte-identical.
//!
//! WIRE FORMAT: the server serializes `BatchInput` with bincode 2.x through its
//! serde path and the standard configuration (see `crate::wire`). This module
//! parses the same bytes, but drives that same configuration through bincode
//! 2's `OwnedSerdeDecoder`, so the collecting path and the streaming path stay
//! byte-identical. Only the guest's parsing differs. The field order below MUST
//! match the `#[derive(Deserialize)]` field order of `BatchInput`/`BlockInput`
//! in `types.rs`; the `streaming_provendb_matches_collecting` regression test
//! guards against drift.

use std::collections::HashMap;

use bincode::de::read::SliceReader;
use bincode::serde::OwnedSerdeDecoder;
use revm::primitives::{Address, B256};
use serde::de::{self, DeserializeSeed, Deserializer, SeqAccess, Visitor};
use serde::Deserialize;

use super::proven_db::{self, ProvenDB};
use crate::merkle::StorageProof;
use crate::types::*;

/// Field-name arrays. Bincode (non-self-describing) uses only the *length* of
/// these to size the positional field sequence, but the real names document the
/// exact wire order the visitors below must reproduce.
const BATCH_INPUT_FIELDS: &[&str] = &[
    "version",
    "chain_id",
    "spec_id",
    "protocol_version_minor",
    "blocks",
    "batch_meta",
    "bytecodes",
];

const BLOCK_INPUT_FIELDS: &[&str] = &[
    "number",
    "timestamp",
    "base_fee",
    "gas_limit",
    "coinbase",
    "prev_randao",
    "transactions",
    "account_preimages",
    "block_hashes",
    "storage_proofs",
    "block_header_hash",
    "l2_to_l1_logs",
    "expected_tree_root",
];

/// Mutable accumulator threaded through the seed tower.
struct StreamState {
    /// The verified storage values, built incrementally as proofs stream in.
    /// `entry().or_insert()` => first block to prove a key wins (identical to
    /// the collecting path).
    verified_storage: HashMap<B256, Option<B256>>,
    /// The single pre-state root recovered by the current block's proofs. Every
    /// proof in a block must recover the same root; that root is later checked
    /// against the block's expected pre-state root. `None` until the block's
    /// first proof (or if the block has no proofs).
    current_block_recovered_root: Option<B256>,
    /// Per-block recovered root, in block order, for the deferred equality
    /// check against `expected_root_for_block` once `batch_meta` is parsed.
    block_recovered_roots: Vec<Option<B256>>,
}

/// Pull the next positional field, erroring like the derived impl if the
/// sequence ends early.
macro_rules! field {
    ($seq:expr, $idx:expr) => {
        $seq.next_element()?
            .ok_or_else(|| de::Error::invalid_length($idx, &"more BatchInput/BlockInput fields"))?
    };
}

// --- top of tower: BatchInput -------------------------------------------------

struct BatchInputSeed<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> DeserializeSeed<'de> for BatchInputSeed<'a> {
    type Value = BatchInput;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<BatchInput, D::Error> {
        d.deserialize_struct(
            "BatchInput",
            BATCH_INPUT_FIELDS,
            BatchInputVisitor { state: self.state },
        )
    }
}

struct BatchInputVisitor<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> Visitor<'de> for BatchInputVisitor<'a> {
    type Value = BatchInput;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("a bincode-encoded BatchInput")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<BatchInput, A::Error> {
        let version: u32 = field!(seq, 0);
        let chain_id: u64 = field!(seq, 1);
        let spec_id: u8 = field!(seq, 2);
        let protocol_version_minor: u32 = field!(seq, 3);
        let blocks = seq
            .next_element_seed(BlocksSeed { state: self.state })?
            .ok_or_else(|| de::Error::invalid_length(4, &"blocks field"))?;
        let batch_meta: BatchMeta = field!(seq, 5);
        let bytecodes: Vec<(B256, Vec<u8>)> = field!(seq, 6);

        Ok(BatchInput {
            version,
            chain_id,
            spec_id,
            protocol_version_minor,
            blocks,
            batch_meta,
            bytecodes,
        })
    }
}

// --- blocks sequence ----------------------------------------------------------

struct BlocksSeed<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> DeserializeSeed<'de> for BlocksSeed<'a> {
    type Value = Vec<BlockInput>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Vec<BlockInput>, D::Error> {
        d.deserialize_seq(BlocksVisitor { state: self.state })
    }
}

struct BlocksVisitor<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> Visitor<'de> for BlocksVisitor<'a> {
    type Value = Vec<BlockInput>;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("a sequence of BlockInput")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<BlockInput>, A::Error> {
        // `size_hint` is the wire-supplied sequence length, so an attacker can
        // request a huge reservation from a few bytes. Cap the pre-allocation;
        // the loop still pushes every block the stream actually yields.
        const MAX_BLOCK_PREALLOC: usize = 1 << 16;
        let mut blocks = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_BLOCK_PREALLOC));
        while let Some(block) = seq.next_element_seed(BlockSeed {
            state: &mut *self.state,
        })? {
            blocks.push(block);
        }
        Ok(blocks)
    }
}

// --- one BlockInput -----------------------------------------------------------

struct BlockSeed<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> DeserializeSeed<'de> for BlockSeed<'a> {
    type Value = BlockInput;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<BlockInput, D::Error> {
        d.deserialize_struct(
            "BlockInput",
            BLOCK_INPUT_FIELDS,
            BlockVisitor { state: self.state },
        )
    }
}

struct BlockVisitor<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> Visitor<'de> for BlockVisitor<'a> {
    type Value = BlockInput;

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("a bincode-encoded BlockInput")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<BlockInput, A::Error> {
        // New block: reset the running recovered-root accumulator.
        self.state.current_block_recovered_root = None;

        let number: u64 = field!(seq, 0);
        let timestamp: u64 = field!(seq, 1);
        let base_fee: u64 = field!(seq, 2);
        let gas_limit: u64 = field!(seq, 3);
        let coinbase: Address = field!(seq, 4);
        let prev_randao: B256 = field!(seq, 5);
        let transactions: Vec<TxInput> = field!(seq, 6);
        let account_preimages: Vec<(Address, Vec<u8>)> = field!(seq, 7);
        let block_hashes: Vec<(u64, B256)> = field!(seq, 8);
        // Stream storage_proofs — verify & drop each; collect nothing.
        seq.next_element_seed(StorageProofsSeed {
            state: &mut *self.state,
        })?
        .ok_or_else(|| de::Error::invalid_length(9, &"storage_proofs field"))?;
        let block_header_hash: B256 = field!(seq, 10);
        let l2_to_l1_logs: Vec<L2ToL1LogEntry> = field!(seq, 11);
        let expected_tree_root: B256 = field!(seq, 12);

        // Record this block's recovered root for the deferred equality check
        // (tree_root_before is parsed after all blocks).
        self.state
            .block_recovered_roots
            .push(self.state.current_block_recovered_root);

        Ok(BlockInput {
            number,
            timestamp,
            base_fee,
            gas_limit,
            coinbase,
            prev_randao,
            transactions,
            account_preimages,
            block_hashes,
            // Proofs are verified and dropped above; never read downstream.
            storage_proofs: Vec::new(),
            block_header_hash,
            l2_to_l1_logs,
            expected_tree_root,
        })
    }
}

// --- storage_proofs sequence: the streamed, never-collected part --------------

struct StorageProofsSeed<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> DeserializeSeed<'de> for StorageProofsSeed<'a> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(StorageProofsVisitor { state: self.state })
    }
}

struct StorageProofsVisitor<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> Visitor<'de> for StorageProofsVisitor<'a> {
    type Value = ();

    fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("a sequence of (flat_key, StorageProof)")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        // Each element is verified-and-dropped inside OneProofSeed; we collect
        // nothing, so at most one proof's siblings are ever resident.
        while seq
            .next_element_seed(OneProofSeed {
                state: &mut *self.state,
            })?
            .is_some()
        {}
        Ok(())
    }
}

struct OneProofSeed<'a> {
    state: &'a mut StreamState,
}

impl<'de, 'a> DeserializeSeed<'de> for OneProofSeed<'a> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        // Deserialize exactly one (flat_key, StorageProof) via the derived
        // impls (this allocates the proof's siblings)...
        let (key, proof) = <(B256, StorageProof)>::deserialize(d)?;
        // ...verify it and extract only the small value...
        let (root, value) = proven_db::verify_storage_proof(&key, &proof);
        // ...cross-check intra-block root consistency (the collecting path
        // asserts each proof recovers the block's expected root; here we assert
        // all proofs in a block recover the SAME root and defer the equality to
        // the expected root — together identical to per-proof checking)...
        match self.state.current_block_recovered_root {
            None => self.state.current_block_recovered_root = Some(root),
            Some(existing) => assert_eq!(
                root, existing,
                "storage proofs within one block recover different roots: \
                 {root} vs {existing}"
            ),
        }
        self.state.verified_storage.entry(key).or_insert(value);
        // `proof` (and its merkle siblings) is dropped here.
        Ok(())
    }
}

/// Stream-deserialize a bincode-encoded `BatchInput` and build its `ProvenDB`
/// without ever holding all merkle siblings resident. Returns the
/// proof-stripped `BatchInput` (its `storage_proofs` vectors are empty) plus the
/// verified database. Byte-identical in result to `build_proven_db` over the
/// same input.
pub(super) fn stream_deserialize_and_build_db(
    bytes: &[u8],
) -> Result<(BatchInput, ProvenDB), String> {
    // Drive the same wire configuration as the collecting path (`crate::wire`):
    // bincode 2.x, standard config (little-endian, variable-length integers).
    // `decode_from_slice` reports the bytes read and ignores the rest, so the
    // guest input's zero pad to an 8-byte boundary is harmless here too.
    let mut state = StreamState {
        verified_storage: HashMap::new(),
        current_block_recovered_root: None,
        block_recovered_roots: Vec::new(),
    };

    let mut decoder = OwnedSerdeDecoder::from_reader(SliceReader::new(bytes), crate::wire::config());
    let input: BatchInput = BatchInputSeed { state: &mut state }
        .deserialize(decoder.as_deserializer())
        .map_err(|e| format!("streaming deserialize: {e}"))?;

    let meta = &input.batch_meta;

    // Deferred per-block root check: every block's proofs recovered the same
    // root (asserted during streaming); now confirm it matches that block's
    // expected pre-state root — the equality the collecting path checks
    // per-proof, deferred here because `tree_root_before` is parsed last.
    debug_assert_eq!(input.blocks.len(), state.block_recovered_roots.len());
    for (block, recovered) in input.blocks.iter().zip(&state.block_recovered_roots) {
        if let Some(root) = recovered {
            let expected = proven_db::expected_root_for_block(block, meta);
            assert_eq!(
                *root, *expected,
                "proof recovers root {root}, expected {expected}"
            );
        }
    }

    // Build the remaining ProvenDB components with the SAME helpers the
    // collecting path uses => byte-identical database.
    let bytecodes = proven_db::load_bytecodes(&input.bytecodes);
    let verified_accounts =
        proven_db::build_verified_accounts(&input.blocks, &state.verified_storage, &bytecodes);
    // The BLOCKHASH map is seeded from authenticated data during execution, not
    // from the witness; construction leaves it empty and only runs the
    // witness-consistency cross-check.
    proven_db::verify_witness_block_hashes(&input.blocks, meta);

    let proven_db = ProvenDB::from_parts(
        state.verified_storage,
        verified_accounts,
        bytecodes,
        HashMap::new(),
    );

    Ok((input, proven_db))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{self, SlotProofEntry, TreeLeaf};
    use revm::primitives::U256;

    fn compress(l: &B256, r: &B256) -> B256 {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(l.as_slice());
        b[32..].copy_from_slice(r.as_slice());
        merkle::blake2s(&b)
    }

    /// Dense tree over MIN/MAX guards (idx 0,1) + `data` leaves (idx 2..) with a
    /// correct sorted linked list. Returns (root, leaves by index, per-leaf
    /// 64-long sibling paths). Produces proofs that verify against `root`.
    fn build_dense_tree(data: &[(B256, B256)]) -> (B256, Vec<(u64, TreeLeaf)>, Vec<Vec<B256>>) {
        let mut recs: Vec<(u64, B256, B256)> =
            vec![(0, B256::ZERO, B256::ZERO), (1, B256::repeat_byte(0xff), B256::ZERO)];
        for (i, (k, v)) in data.iter().enumerate() {
            recs.push((2 + i as u64, *k, *v));
        }
        let mut order: Vec<usize> = (0..recs.len()).collect();
        order.sort_by(|&a, &b| recs[a].1.cmp(&recs[b].1));
        let mut next = vec![0u64; recs.len()];
        for w in order.windows(2) {
            next[w[0]] = recs[w[1]].0;
        }
        next[*order.last().unwrap()] = 1;

        let leaves: Vec<(u64, TreeLeaf)> = recs
            .iter()
            .zip(&next)
            .map(|((idx, k, v), n)| (*idx, TreeLeaf { key: *k, value: *v, next_index: *n }))
            .collect();

        let mut levels: Vec<Vec<B256>> = vec![leaves
            .iter()
            .map(|(_, l)| merkle::hash_leaf(&l.key, &l.value, l.next_index))
            .collect()];
        while levels.last().unwrap().len() > 1 {
            let d = levels.len() - 1;
            let cur = levels.last().unwrap();
            let nl: Vec<B256> = (0..cur.len().div_ceil(2))
                .map(|i| {
                    let l = cur[2 * i];
                    let r = cur.get(2 * i + 1).copied().unwrap_or(merkle::empty_subtree_hash(d as u8));
                    compress(&l, &r)
                })
                .collect();
            levels.push(nl);
        }
        let mut root = levels.last().unwrap()[0];
        for d in (levels.len() - 1)..(merkle::TREE_DEPTH as usize) {
            root = compress(&root, &merkle::empty_subtree_hash(d as u8));
        }

        let siblings: Vec<Vec<B256>> = (0..leaves.len() as u64)
            .map(|i| {
                (0..merkle::TREE_DEPTH as usize)
                    .map(|d| {
                        let pos = ((i >> d) ^ 1) as usize;
                        levels
                            .get(d)
                            .and_then(|lvl| lvl.get(pos).copied())
                            .unwrap_or(merkle::empty_subtree_hash(d as u8))
                    })
                    .collect()
            })
            .collect();
        (root, leaves, siblings)
    }

    fn enc_props(nonce: u64, balance: U256) -> Vec<u8> {
        let mut d = vec![0u8; 124];
        d[8..16].copy_from_slice(&nonce.to_be_bytes());
        d[16..48].copy_from_slice(&balance.to_be_bytes::<32>());
        d
    }

    fn empty_ring_blake() -> B256 {
        crate::commitment::block_hashes_blake(&[B256::ZERO; 255], &B256::ZERO)
    }

    /// A fixture that exercises every ProvenDB component: an Existing account
    /// proof, an Existing storage-slot proof, a NonExisting proof, one bytecode,
    /// account preimages (existing + non-existent), block hashes, over two
    /// blocks.
    fn build_fixture() -> BatchInput {
        let acct: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let contract: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let code = vec![0x60u8, 0x00, 0x60, 0x00, 0xf3]; // PUSH1 0 PUSH1 0 RETURN
        let code_hash = crate::hash::keccak256(&code);

        let acct_props = enc_props(7, U256::from(123u64));
        let acct_flat = merkle::derive_account_properties_key(&acct.into_array());

        // Contract account props carrying the code hash (observable + real).
        let mut contract_props = enc_props(1, U256::from(5u64));
        contract_props[0..8].copy_from_slice(&1u64.to_be_bytes()); // versioning=1 (evm)
        contract_props[48..80].copy_from_slice(code_hash.as_slice());
        contract_props[88..120].copy_from_slice(code_hash.as_slice());
        let contract_flat = merkle::derive_account_properties_key(&contract.into_array());

        // One contract storage slot.
        let slot = B256::from(U256::from(42u64));
        let slot_flat = merkle::derive_flat_storage_key(&contract.into_array(), &slot);
        let slot_val = B256::from(U256::from(99u64));

        let data = vec![
            (acct_flat, merkle::AccountProperties::hash(&acct_props)),
            (contract_flat, merkle::AccountProperties::hash(&contract_props)),
            (slot_flat, slot_val),
        ];
        let (root, leaves, siblings) = build_dense_tree(&data);

        let existing = |leaf_idx: usize| -> StorageProof {
            let (idx, leaf) = &leaves[leaf_idx];
            StorageProof::Existing(SlotProofEntry {
                index: *idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[leaf_idx].clone(),
            })
        };

        // NonExisting proof for a missing key (a non-existent account).
        let missing: Address = "0x3000000000000000000000000000000000000003".parse().unwrap();
        let missing_flat = merkle::derive_account_properties_key(&missing.into_array());
        let (li, lleaf) = leaves
            .iter()
            .filter(|(_, l)| l.key < missing_flat)
            .max_by_key(|(_, l)| l.key)
            .unwrap();
        let (ri, rleaf) = leaves.iter().find(|(i, _)| *i == lleaf.next_index).unwrap();
        let mk_entry = |i: u64, l: &TreeLeaf| SlotProofEntry {
            index: i,
            value: l.value,
            next_index: l.next_index,
            siblings: siblings[i as usize].clone(),
        };
        let non_existing = StorageProof::NonExisting {
            left_neighbor: merkle::NeighborProofEntry {
                entry: mk_entry(*li, lleaf),
                leaf_key: lleaf.key,
            },
            right_neighbor: merkle::NeighborProofEntry {
                entry: mk_entry(*ri, rleaf),
                leaf_key: rleaf.key,
            },
        };

        let block = |number: u64, proofs: Vec<(B256, StorageProof)>, preimages: Vec<(Address, Vec<u8>)>| BlockInput {
            number,
            timestamp: 1_700_000_000 + number,
            base_fee: 7,
            gas_limit: 1_000_000,
            coinbase: acct,
            prev_randao: B256::from([1u8; 32]),
            transactions: vec![],
            account_preimages: preimages,
            block_hashes: vec![(number.saturating_sub(1), B256::repeat_byte(number as u8))],
            storage_proofs: proofs,
            block_header_hash: B256::ZERO,
            l2_to_l1_logs: vec![],
            expected_tree_root: B256::ZERO,
        };

        BatchInput {
            version: BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
            blocks: vec![
                // Block 1: account + contract proofs; account preimages.
                // leaves[0..2] are the MIN/MAX guards; data leaves start at 2.
                block(
                    1,
                    vec![(acct_flat, existing(2)), (contract_flat, existing(3))],
                    vec![(acct, acct_props.clone()), (contract, contract_props.clone())],
                ),
                // Block 2: slot proof + a NonExisting proof; non-existent preimage.
                block(
                    2,
                    vec![(slot_flat, existing(4)), (missing_flat, non_existing)],
                    vec![],
                ),
            ],
            batch_meta: BatchMeta {
                tree_root_before: root,
                leaf_count_before: leaves.len() as u64,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: empty_ring_blake(),
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
                interop_proofs: None,
            },
            bytecodes: vec![(code_hash, code)],
        }
    }

    /// The streaming builder must produce a byte-identical `ProvenDB` and a
    /// proof-stripped `BatchInput` that matches the full parse in every field
    /// except the (intentionally dropped) storage_proofs.
    #[test]
    fn streaming_provendb_matches_collecting() {
        let input = build_fixture();
        let bytes = crate::wire::encode(&input);

        // Collecting path.
        let full: BatchInput = crate::wire::decode(&bytes).unwrap();
        let db_a = proven_db::build_proven_db(&full);

        // Streaming path.
        let (stripped, db_b) = stream_deserialize_and_build_db(&bytes).unwrap();

        // 1. All four ProvenDB component maps are identical.
        let (vs_a, va_a, bc_a, bh_a) = db_a.parts_for_test();
        let (vs_b, va_b, bc_b, bh_b) = db_b.parts_for_test();
        assert_eq!(vs_a, vs_b, "verified_storage differs");
        assert_eq!(va_a, va_b, "verified_accounts differs");
        assert_eq!(bc_a, bc_b, "bytecodes differ");
        assert_eq!(bh_a, bh_b, "block_hashes differ");

        // 2. The stripped BatchInput equals the full one with proofs cleared —
        //    proves every other field round-tripped through the seed tower.
        let mut full_cleared = full.clone();
        for b in &mut full_cleared.blocks {
            b.storage_proofs.clear();
        }
        assert_eq!(
            crate::wire::encode(&stripped),
            crate::wire::encode(&full_cleared),
            "stripped BatchInput diverges from the full parse (minus proofs)"
        );

        // 3. And the streaming path actually stripped the proofs.
        assert!(stripped.blocks.iter().all(|b| b.storage_proofs.is_empty()));
        // Sanity: the fixture really had proofs.
        assert!(full.blocks.iter().any(|b| !b.storage_proofs.is_empty()));
    }
}
