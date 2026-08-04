//! Blake2s-256 binary Merkle tree proof verification for the ZKsync OS flat storage model.
//!
//! The storage tree is a depth-64 binary Merkle tree with Blake2s-256 as the hash function.
//! Leaves are `(key: B256, value: B256, next_index: u64)` forming a sorted linked list.
//! This module verifies inclusion/exclusion proofs against a known root hash.

use alloy_primitives::B256;
use blake2::digest::FixedOutput;
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

/// Maximum tree depth (64 bits of key space).
pub const TREE_DEPTH: u8 = 64;

// ---------------------------------------------------------------------------
// Blake2s helpers
// ---------------------------------------------------------------------------

pub fn blake2s(data: &[u8]) -> B256 {
    let mut h = Blake2s256::new();
    h.update(data);
    B256::from_slice(&h.finalize_fixed())
}

fn blake2s_compress(lhs: &B256, rhs: &B256) -> B256 {
    let mut h = Blake2s256::new();
    h.update(lhs.as_slice());
    h.update(rhs.as_slice());
    B256::from_slice(&h.finalize_fixed())
}

/// Hash a leaf: Blake2s(key || value || next_index_le_8).
pub fn hash_leaf(key: &B256, value: &B256, next_index: u64) -> B256 {
    let mut buf = [0u8; 72]; // 32 + 32 + 8
    buf[..32].copy_from_slice(key.as_slice());
    buf[32..64].copy_from_slice(value.as_slice());
    buf[64..72].copy_from_slice(&next_index.to_le_bytes());
    blake2s(&buf)
}

/// Precomputed empty subtree hashes for each depth 0..=64.
fn empty_subtree_hashes() -> &'static Vec<B256> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Vec<B256>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let empty_leaf = hash_leaf(&B256::ZERO, &B256::ZERO, 0);
        let mut hashes = vec![empty_leaf];
        for _ in 0..TREE_DEPTH {
            let prev = *hashes.last().unwrap();
            hashes.push(blake2s_compress(&prev, &prev));
        }
        hashes
    })
}

/// Get the empty subtree hash at the given depth.
pub fn empty_subtree_hash(depth: u8) -> B256 {
    empty_subtree_hashes()[depth as usize]
}

/// Returns a Vec of empty subtree hashes for each depth 0..TREE_DEPTH.
pub fn empty_subtree_hashes_vec() -> Vec<B256> {
    empty_subtree_hashes().clone()
}

// ---------------------------------------------------------------------------
// Proof types
// ---------------------------------------------------------------------------

/// Merkle proof entry for a single storage slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotProofEntry {
    pub index: u64,
    pub value: B256,
    pub next_index: u64,
    /// Sibling hashes from leaf (depth 0) upward. If shorter than TREE_DEPTH,
    /// missing entries are filled with `empty_subtree_hash(depth)`.
    pub siblings: Vec<B256>,
}

impl SlotProofEntry {
    /// Verify this proof entry for the given leaf key and recover the tree root hash.
    pub fn recover_root(&self, leaf_key: &B256) -> B256 {
        let empty = empty_subtree_hashes();
        let mut hash = hash_leaf(leaf_key, &self.value, self.next_index);
        let mut idx = self.index;
        for depth in 0..TREE_DEPTH {
            let sibling = self
                .siblings
                .get(depth as usize)
                .copied()
                .unwrap_or(empty[depth as usize]);
            hash = if idx % 2 == 0 {
                blake2s_compress(&hash, &sibling)
            } else {
                blake2s_compress(&sibling, &hash)
            };
            idx /= 2;
        }
        hash
    }
}

/// Proof for a single storage slot (existing or non-existing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageProof {
    /// The key exists in the tree.
    Existing(SlotProofEntry),
    /// The key does NOT exist. Proved by showing two adjacent leaves in the
    /// sorted linked list that bracket the missing key.
    NonExisting {
        left_neighbor: NeighborProofEntry,
        right_neighbor: NeighborProofEntry,
    },
}

/// Neighbor entry used in non-existence proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborProofEntry {
    pub entry: SlotProofEntry,
    pub leaf_key: B256,
}

impl StorageProof {
    /// Verify the proof for the given flat storage key and return (root_hash, value).
    /// For existing keys, value is Some. For non-existing, value is None.
    pub fn verify(&self, flat_key: &B256) -> Result<(B256, Option<B256>), ProofError> {
        match self {
            StorageProof::Existing(entry) => {
                let root = entry.recover_root(flat_key);
                Ok((root, Some(entry.value)))
            }
            StorageProof::NonExisting {
                left_neighbor,
                right_neighbor,
            } => {
                if left_neighbor.leaf_key >= *flat_key {
                    return Err(ProofError::LeftNeighborNotSmaller);
                }
                if *flat_key >= right_neighbor.leaf_key {
                    return Err(ProofError::RightNeighborNotLarger);
                }
                if left_neighbor.entry.next_index != right_neighbor.entry.index {
                    return Err(ProofError::NeighborsNotAdjacent);
                }
                let root_left = left_neighbor.entry.recover_root(&left_neighbor.leaf_key);
                let root_right = right_neighbor.entry.recover_root(&right_neighbor.leaf_key);
                if root_left != root_right {
                    return Err(ProofError::RootMismatch);
                }
                Ok((root_left, None))
            }
        }
    }
}

#[derive(Debug)]
pub enum ProofError {
    LeftNeighborNotSmaller,
    RightNeighborNotLarger,
    NeighborsNotAdjacent,
    RootMismatch,
}

impl core::fmt::Display for ProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LeftNeighborNotSmaller => write!(f, "left neighbor key >= queried key"),
            Self::RightNeighborNotLarger => write!(f, "right neighbor key <= queried key"),
            Self::NeighborsNotAdjacent => {
                write!(f, "neighbor leaves not adjacent in linked list")
            }
            Self::RootMismatch => write!(f, "left and right neighbor recover different roots"),
        }
    }
}

impl std::error::Error for ProofError {}

// ---------------------------------------------------------------------------
// Batch tree update — verify old root, apply writes, compute new root
// ---------------------------------------------------------------------------

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

/// Batch tree proof for verifying the old root and computing the new root
/// after applying a set of writes.
///
/// `sorted_leaves` is the pre-state of every touched leaf plus any *anchor*
/// leaves: untouched leaves included so that the old-root pass authenticates
/// tree regions the new-root pass needs as siblings. The new root is a pure
/// function of (authenticated old state, verified write entries) — there is no
/// trusted post-state input of any kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTreeUpdate {
    pub operations: Vec<WriteOp>,
    pub entries: Vec<(B256, B256)>,
    pub sorted_leaves: Vec<(u64, TreeLeaf)>,
    /// Intermediate sibling hashes for reconstructing the OLD root from
    /// sorted_leaves, in traversal order. Authenticated by the old-root check.
    pub intermediate_hashes: Vec<B256>,
    pub leaf_count_before: u64,
}

impl BatchTreeUpdate {
    /// Verify the old root matches `expected_old_root`, apply writes, and return
    /// (new_root_hash, new_leaf_count).
    ///
    /// Single-pass O(W) tree update: a SINGLE bottom-up walk computes the old and new
    /// roots together, carrying an `(old_hash, new_hash)` pair per touched
    /// position and consuming `intermediate_hashes` for off-path siblings
    /// (which are untouched subtrees, hence identical in the old and new trees).
    /// Interior levels are released as the walk ascends, so the working set is
    /// `O(W)` (touched nodes at one level) rather than the previous
    /// `O(W·depth)` `authenticated` HashMap — the write-spam OOM dominator.
    ///
    /// Soundness is preserved bit-for-bit (see the reference two-pass under
    /// `#[cfg(test)]` and the extensive A/B regression tests): the off-path
    /// sibling of every position is resolved by the SAME region rule the
    /// previous `resolve_sibling` used — a sibling subtree that begins at or
    /// beyond `leaf_count_before` is a provably-empty subtree (the old tree is
    /// empty there and inserts are dense, so an off-path node there holds
    /// nothing), and anything below `leaf_count_before` must be supplied by an
    /// `intermediate_hashes` entry (an anchor). Inserted leaves carry
    /// `old = empty_subtree_hash(0)` and ascend as empty subtrees until they
    /// merge with an authenticated old node, reproducing the previous code's
    /// empty-right-sibling behaviour at the tree's populated boundary. A witness
    /// missing an anchor makes the old root mismatch (or exhausts the
    /// intermediate hashes) — a hard failure, exactly as before.
    pub fn apply(&self, expected_old_root: &B256) -> (B256, u64) {
        let (new_leaves, next_tree_index) = self.apply_writes();
        let (old_root, new_root) = self.walk_old_and_new(&new_leaves);
        assert_eq!(
            old_root, *expected_old_root,
            "batch tree update: old root mismatch: computed {old_root}, expected {expected_old_root}"
        );
        (new_root, next_tree_index)
    }

    /// Apply the write operations to a clone of `sorted_leaves`, returning the
    /// post-write leaf set (sorted by index) and the new leaf count. This is the
    /// unchanged write-application logic; only the root computation changed.
    fn apply_writes(&self) -> (Vec<(u64, TreeLeaf)>, u64) {
        let mut leaves: Vec<(u64, TreeLeaf)> = self.sorted_leaves.clone();
        let mut next_tree_index = self.leaf_count_before;

        // Index map: tree_index -> position in `leaves` vec, for O(1) lookup.
        let mut pos_of: std::collections::HashMap<u64, usize> = leaves
            .iter()
            .enumerate()
            .map(|(pos, (idx, _))| (*idx, pos))
            .collect();

        for (op, (key, new_value)) in self.operations.iter().zip(&self.entries) {
            match op {
                WriteOp::Update { index } => {
                    let pos = pos_of[index];
                    assert_eq!(leaves[pos].1.key, *key, "update key mismatch");
                    leaves[pos].1.value = *new_value;
                }
                WriteOp::Insert { prev_index } => {
                    let this_index = next_tree_index;
                    next_tree_index += 1;

                    let prev_pos = pos_of[prev_index];
                    let old_next = leaves[prev_pos].1.next_index;

                    // Linked-list ordering: the predecessor must bracket the
                    // new key together with its successor, or non-existence
                    // semantics of the resulting tree are corrupted. The
                    // successor leaf must be present in the witness set.
                    assert!(
                        leaves[prev_pos].1.key < *key,
                        "insert ordering violation: predecessor key {} >= inserted key {key}",
                        leaves[prev_pos].1.key,
                    );
                    let next_pos = *pos_of
                        .get(&old_next)
                        .unwrap_or_else(|| panic!("successor leaf {old_next} missing from witness"));
                    assert!(
                        *key < leaves[next_pos].1.key,
                        "insert ordering violation: inserted key {key} >= successor key {}",
                        leaves[next_pos].1.key,
                    );

                    let new_pos = leaves.len();
                    leaves.push((
                        this_index,
                        TreeLeaf {
                            key: *key,
                            value: *new_value,
                            next_index: old_next,
                        },
                    ));
                    pos_of.insert(this_index, new_pos);

                    // Update prev leaf's next_index (re-lookup pos since vec wasn't reordered)
                    leaves[prev_pos].1.next_index = this_index;
                }
            }
        }

        leaves.sort_by_key(|(idx, _)| *idx);
        (leaves, next_tree_index)
    }

    /// Streaming tree-update core: one bottom-up pass over the union of the old and new touched
    /// positions, carrying `(old_hash, new_hash)` per node. Returns
    /// `(old_root, new_root)`.
    ///
    /// The combined depth-0 list is built from `new_leaves` (sorted by index).
    /// Each entry's `new_hash` is the post-write leaf hash; its `old_hash` is
    /// the pre-write leaf hash (from `sorted_leaves`) for a pre-existing index,
    /// or `empty_subtree_hash(0)` for an inserted index (which was empty in the
    /// old tree). Off-path siblings are resolved by `resolve_offpath_sibling`
    /// and are, by construction, identical in the old and new trees, so a single
    /// value serves both sides. `intermediate_hashes` is consumed in traversal
    /// order (and must be fully consumed) — matching the previous pass-1 order.
    fn walk_old_and_new(&self, new_leaves: &[(u64, TreeLeaf)]) -> (B256, B256) {
        let empty = empty_subtree_hashes();
        let mut hashes_iter = self.intermediate_hashes.iter();

        // Pre-write leaf by index, for the old-side depth-0 hashes. Only
        // pre-existing indices (< leaf_count_before) are looked up here.
        let orig_by_idx: std::collections::HashMap<u64, &TreeLeaf> =
            self.sorted_leaves.iter().map(|(idx, l)| (*idx, l)).collect();

        // Depth-0 combined nodes: (index, old_hash, new_hash), sorted by index.
        let mut level: Vec<(u64, B256, B256)> = new_leaves
            .iter()
            .map(|(idx, new_leaf)| {
                let new_hash = hash_leaf(&new_leaf.key, &new_leaf.value, new_leaf.next_index);
                let old_hash = if *idx < self.leaf_count_before {
                    let o = orig_by_idx
                        .get(idx)
                        .expect("pre-existing touched leaf must be present in sorted_leaves");
                    hash_leaf(&o.key, &o.value, o.next_index)
                } else {
                    // Inserted index: the old tree held an empty leaf here.
                    empty[0]
                };
                (*idx, old_hash, new_hash)
            })
            .collect();

        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next: Vec<(u64, B256, B256)> = Vec::with_capacity(level.len().div_ceil(2) + 1);
            while i < level.len() {
                let (idx, old, new) = level[i];
                let (parent_old, parent_new) = if idx % 2 == 1 {
                    // Odd (right child): left sibling is off-path. Its left
                    // neighbour, if computed, would have paired with it while
                    // that even node was processed, so reaching an odd node
                    // standalone means the left sibling is genuinely off-path.
                    let sib = self.resolve_offpath_sibling(depth, idx - 1, empty, &mut hashes_iter);
                    i += 1;
                    (blake2s_compress(&sib, &old), blake2s_compress(&sib, &new))
                } else if level.get(i + 1).is_some_and(|(nidx, _, _)| *nidx == idx + 1) {
                    // Even (left child) with the computed right sibling present.
                    let (_, rold, rnew) = level[i + 1];
                    i += 2;
                    (blake2s_compress(&old, &rold), blake2s_compress(&new, &rnew))
                } else {
                    // Even (left child) with off-path right sibling.
                    let sib = self.resolve_offpath_sibling(depth, idx + 1, empty, &mut hashes_iter);
                    i += 1;
                    (blake2s_compress(&old, &sib), blake2s_compress(&new, &sib))
                };
                next.push((idx / 2, parent_old, parent_new));
            }
            level = next;
        }

        assert!(
            hashes_iter.next().is_none(),
            "not all intermediate hashes consumed"
        );
        debug_assert_eq!(level.len(), 1, "walk did not reduce to a single root");
        (level[0].1, level[0].2)
    }

    /// Resolve an off-path sibling (identical for the old and new trees).
    ///
    /// A sibling subtree that begins at or beyond `leaf_count_before` is
    /// provably empty — the old tree is empty there and any inserted leaf in
    /// that region would be a computed node (hence paired, not off-path). This
    /// is exactly the empty rule of the previous `resolve_sibling`, and it also
    /// reproduces the previous pass-1 "rightmost node uses empty" behaviour.
    /// Otherwise the sibling is an untouched old subtree supplied as the next
    /// `intermediate_hashes` entry (an anchor); running out is a hard failure.
    fn resolve_offpath_sibling(
        &self,
        depth: u8,
        sib_idx: u64,
        empty: &[B256],
        hashes_iter: &mut std::slice::Iter<'_, B256>,
    ) -> B256 {
        let subtree_start = sib_idx << depth;
        if subtree_start >= self.leaf_count_before {
            empty[depth as usize]
        } else {
            *hashes_iter.next().expect("ran out of intermediate hashes")
        }
    }

    /// Reference two-pass implementation, retained as the A/B test oracle.
    ///
    /// This is the two-pass reference `apply`: pass 1 reconstructs the old root while
    /// recording every node into an `authenticated` map (`O(W·depth)`), then
    /// pass 2 recomputes the new root from that map. The streaming `apply` above
    /// must reproduce its `(new_root, new_leaf_count)` bit-for-bit.
    #[cfg(any(test, feature = "bench-internals"))]
    pub fn apply_reference(&self, expected_old_root: &B256) -> (B256, u64) {
        let mut authenticated: std::collections::HashMap<(u8, u64), B256> =
            std::collections::HashMap::new();
        let old_root =
            self.zip_and_record(&self.sorted_leaves, self.leaf_count_before, &mut authenticated);
        assert_eq!(
            old_root, *expected_old_root,
            "batch tree update: old root mismatch: computed {old_root}, expected {expected_old_root}"
        );

        let (leaves, next_tree_index) = self.apply_writes();
        let new_root = self.zip_from_authenticated(&leaves, next_tree_index, &authenticated);
        (new_root, next_tree_index)
    }

    /// Reconstruct the old root from `sorted_leaves`, consuming
    /// `intermediate_hashes` in traversal order and recording every node this
    /// pass touches (leaf hashes, consumed siblings, computed internal nodes)
    /// into `authenticated`, keyed by (depth, index-at-depth).
    #[cfg(any(test, feature = "bench-internals"))]
    fn zip_and_record(
        &self,
        sorted_leaves: &[(u64, TreeLeaf)],
        leaf_count: u64,
        authenticated: &mut std::collections::HashMap<(u8, u64), B256>,
    ) -> B256 {
        let empty_hashes = empty_subtree_hashes();
        let mut hashes_iter = self.intermediate_hashes.iter();

        let mut node_hashes: Vec<(u64, B256)> = sorted_leaves
            .iter()
            .map(|(idx, leaf)| (*idx, hash_leaf(&leaf.key, &leaf.value, leaf.next_index)))
            .collect();
        for (idx, h) in &node_hashes {
            authenticated.insert((0, *idx), *h);
        }

        let mut last_idx_on_level = leaf_count - 1;

        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next_level_i = 0;

            while i < node_hashes.len() {
                let (current_idx, current_hash) = node_hashes[i];

                let next_level_hash = if current_idx % 2 == 1 {
                    i += 1;
                    let lhs = hashes_iter.next().expect("ran out of intermediate hashes");
                    authenticated.insert((depth, current_idx - 1), *lhs);
                    blake2s_compress(lhs, &current_hash)
                } else if node_hashes
                    .get(i + 1)
                    .is_some_and(|(next_idx, _)| *next_idx == current_idx + 1)
                {
                    let next_hash = node_hashes[i + 1].1;
                    i += 2;
                    blake2s_compress(&current_hash, &next_hash)
                } else {
                    i += 1;
                    let rhs = if current_idx == last_idx_on_level {
                        empty_hashes[depth as usize]
                    } else {
                        let h = *hashes_iter.next().expect("ran out of intermediate hashes");
                        authenticated.insert((depth, current_idx + 1), h);
                        h
                    };
                    blake2s_compress(&current_hash, &rhs)
                };

                node_hashes[next_level_i] = (current_idx / 2, next_level_hash);
                authenticated.insert((depth + 1, current_idx / 2), next_level_hash);
                next_level_i += 1;
            }

            node_hashes.truncate(next_level_i);
            last_idx_on_level /= 2;
        }

        assert!(hashes_iter.next().is_none(), "not all intermediate hashes consumed");
        node_hashes[0].1
    }

    /// Compute the new root over the post-write leaf set. Every sibling not in
    /// the computed set must be either authenticated by the old-root pass or a
    /// provably-empty subtree; anything else is a hard error.
    ///
    /// Empty-subtree rule: inserted leaves are assigned dense indices starting
    /// at `leaf_count_before`, so a sibling subtree that starts at or beyond
    /// `leaf_count_before` and contains no computed node holds no leaves at
    /// all in the new tree.
    #[cfg(any(test, feature = "bench-internals"))]
    fn zip_from_authenticated(
        &self,
        sorted_leaves: &[(u64, TreeLeaf)],
        leaf_count: u64,
        authenticated: &std::collections::HashMap<(u8, u64), B256>,
    ) -> B256 {
        let empty_hashes = empty_subtree_hashes();
        let _ = leaf_count;

        let mut node_hashes: Vec<(u64, B256)> = sorted_leaves
            .iter()
            .map(|(idx, leaf)| (*idx, hash_leaf(&leaf.key, &leaf.value, leaf.next_index)))
            .collect();

        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next_level_i = 0;

            while i < node_hashes.len() {
                let (current_idx, current_hash) = node_hashes[i];
                let sibling_idx = current_idx ^ 1;

                let paired_with_computed = node_hashes
                    .get(i + 1)
                    .is_some_and(|(next_idx, _)| *next_idx == sibling_idx);

                let next_level_hash = if paired_with_computed {
                    let next_hash = node_hashes[i + 1].1;
                    i += 2;
                    blake2s_compress(&current_hash, &next_hash)
                } else {
                    i += 1;
                    let sibling_hash = Self::resolve_sibling(
                        depth,
                        sibling_idx,
                        self.leaf_count_before,
                        authenticated,
                        &empty_hashes,
                    );
                    if current_idx % 2 == 1 {
                        blake2s_compress(&sibling_hash, &current_hash)
                    } else {
                        blake2s_compress(&current_hash, &sibling_hash)
                    }
                };

                node_hashes[next_level_i] = (current_idx / 2, next_level_hash);
                next_level_i += 1;
            }

            node_hashes.truncate(next_level_i);
        }

        node_hashes[0].1
    }

    /// Resolve an off-path sibling for the new-root pass.
    #[cfg(any(test, feature = "bench-internals"))]
    fn resolve_sibling(
        depth: u8,
        sibling_idx: u64,
        leaf_count_before: u64,
        authenticated: &std::collections::HashMap<(u8, u64), B256>,
        empty_hashes: &[B256],
    ) -> B256 {
        if let Some(h) = authenticated.get(&(depth, sibling_idx)) {
            return *h;
        }
        let subtree_start = sibling_idx << depth;
        if subtree_start >= leaf_count_before {
            return empty_hashes[depth as usize];
        }
        panic!(
            "unauthenticated sibling at depth {depth}, index {sibling_idx}: \
             the witness must include an anchor leaf for this subtree"
        );
    }
}

// ---------------------------------------------------------------------------
// Account properties decoding (from 0x8003 storage)
// ---------------------------------------------------------------------------

/// Account properties as stored in the merkle tree at address 0x8003.
/// Layout: versioning(8) | nonce(8) | balance(32) | bytecode_hash(32) |
///         unpadded_code_len(4) | artifacts_len(4) | observable_bytecode_hash(32) |
///         observable_bytecode_len(4) = 124 bytes.
#[derive(Debug, Clone)]
pub struct AccountProperties {
    pub versioning: u64,
    pub nonce: u64,
    pub balance: [u8; 32],
    pub bytecode_hash: B256,
    pub unpadded_code_len: u32,
    pub artifacts_len: u32,
    pub observable_bytecode_hash: B256,
    pub observable_bytecode_len: u32,
}

/// Reason an account-properties blob failed to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountPropertiesDecodeError {
    /// The blob length differs from [`AccountProperties::ENCODED_SIZE`].
    WrongLength { expected: usize, actual: usize },
}

impl core::fmt::Display for AccountPropertiesDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => write!(
                f,
                "account properties blob must be exactly {expected} bytes, got {actual}"
            ),
        }
    }
}

impl std::error::Error for AccountPropertiesDecodeError {}

/// Read the `N` bytes at `offset` from an account-properties blob. A read past
/// the end of the blob returns an error, so the decoder holds no index that
/// can panic on a short blob.
fn read_account_properties_field<const N: usize>(
    data: &[u8],
    offset: usize,
) -> Result<[u8; N], AccountPropertiesDecodeError> {
    data.get(offset..offset.saturating_add(N))
        .and_then(|field| <[u8; N]>::try_from(field).ok())
        .ok_or(AccountPropertiesDecodeError::WrongLength {
            expected: AccountProperties::ENCODED_SIZE,
            actual: data.len(),
        })
}

impl AccountProperties {
    pub const ENCODED_SIZE: usize = 124;

    /// Decode a 124-byte account-properties blob.
    ///
    /// The host reads these blobs out of the state store, so a wrong length
    /// reaches the caller as an error. Guest-side callers unwrap the result:
    /// inside the zkVM a malformed blob rejects the proof.
    pub fn decode(data: &[u8]) -> Result<Self, AccountPropertiesDecodeError> {
        if data.len() != Self::ENCODED_SIZE {
            return Err(AccountPropertiesDecodeError::WrongLength {
                expected: Self::ENCODED_SIZE,
                actual: data.len(),
            });
        }

        Ok(Self {
            versioning: u64::from_be_bytes(read_account_properties_field(data, 0)?),
            nonce: u64::from_be_bytes(read_account_properties_field(data, 8)?),
            balance: read_account_properties_field(data, 16)?,
            bytecode_hash: B256::from(read_account_properties_field::<32>(data, 48)?),
            unpadded_code_len: u32::from_be_bytes(read_account_properties_field(data, 80)?),
            artifacts_len: u32::from_be_bytes(read_account_properties_field(data, 84)?),
            observable_bytecode_hash: B256::from(read_account_properties_field::<32>(data, 88)?),
            observable_bytecode_len: u32::from_be_bytes(read_account_properties_field(data, 120)?),
        })
    }

    /// Compute the Blake2s hash of the encoded account properties.
    pub fn hash(encoded: &[u8]) -> B256 {
        blake2s(encoded)
    }

}

// ---------------------------------------------------------------------------
// Flat storage key derivation
// ---------------------------------------------------------------------------

/// Derive the flat storage key from (address, storage_slot).
/// flat_key = Blake2s256( zero_pad_12(address_be_20) || slot_be_32 )
pub fn derive_flat_storage_key(address: &[u8; 20], slot: &B256) -> B256 {
    let mut h = Blake2s256::new();
    h.update([0u8; 12]);
    h.update(address);
    h.update(slot.as_slice());
    B256::from_slice(&h.finalize_fixed())
}

/// The special address where account properties are stored.
pub const ACCOUNT_PROPERTIES_ADDRESS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x03,
];

/// Derive the flat key for an account's properties.
/// Stored at address 0x8003, key = left-padded account address.
pub fn derive_account_properties_key(account: &[u8; 20]) -> B256 {
    let mut account_key = B256::ZERO;
    account_key.0[12..32].copy_from_slice(account);
    derive_flat_storage_key(&ACCOUNT_PROPERTIES_ADDRESS, &account_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host build path feeds untrusted state blobs to the decoder, so a
    /// blob of the wrong length must come back as an error. A well-formed blob
    /// must decode every field at its documented offset.
    #[test]
    fn account_properties_decode_reports_wrong_length() {
        for length in [0usize, 1, 123, 125, 256] {
            let error = AccountProperties::decode(&vec![0u8; length])
                .err()
                .unwrap_or_else(|| panic!("a {length}-byte blob must be rejected"));
            assert_eq!(
                error,
                AccountPropertiesDecodeError::WrongLength {
                    expected: AccountProperties::ENCODED_SIZE,
                    actual: length,
                }
            );
        }

        let mut blob = [0u8; AccountProperties::ENCODED_SIZE];
        blob[0..8].copy_from_slice(&0x0101_0100_0000_0000u64.to_be_bytes());
        blob[8..16].copy_from_slice(&7u64.to_be_bytes());
        blob[16..48].copy_from_slice(B256::repeat_byte(0x11).as_slice());
        blob[48..80].copy_from_slice(B256::repeat_byte(0x22).as_slice());
        blob[80..84].copy_from_slice(&23u32.to_be_bytes());
        blob[84..88].copy_from_slice(&8u32.to_be_bytes());
        blob[88..120].copy_from_slice(B256::repeat_byte(0x33).as_slice());
        blob[120..124].copy_from_slice(&23u32.to_be_bytes());

        let props = AccountProperties::decode(&blob).expect("a 124-byte blob must decode");
        assert_eq!(props.versioning, 0x0101_0100_0000_0000);
        assert_eq!(props.nonce, 7);
        assert_eq!(props.balance, [0x11u8; 32]);
        assert_eq!(props.bytecode_hash, B256::repeat_byte(0x22));
        assert_eq!(props.unpadded_code_len, 23);
        assert_eq!(props.artifacts_len, 8);
        assert_eq!(props.observable_bytecode_hash, B256::repeat_byte(0x33));
        assert_eq!(props.observable_bytecode_len, 23);
    }

    #[test]
    fn empty_leaf_hash_matches_server() {
        let expected: B256 =
            "0xe3cdc93b3c2beb30f6a7c7cc45a32da012df9ae1be880e2c074885cb3f4e1e53"
                .parse()
                .unwrap();
        assert_eq!(empty_subtree_hash(0), expected);
    }

    #[test]
    fn empty_level1_hash_matches_server() {
        let expected: B256 =
            "0xc45bfaf4bb5d0fee27d3178b8475155a07a1fa8ada9a15133a9016f7d0435f0f"
                .parse()
                .unwrap();
        assert_eq!(empty_subtree_hash(1), expected);
    }

    #[test]
    fn empty_level63_hash_matches_server() {
        let expected: B256 =
            "0xb720fe53e6bd4e997d967b8649e10036802a4fd3aca6d7dcc43ed9671f41cb31"
                .parse()
                .unwrap();
        assert_eq!(empty_subtree_hash(63), expected);
    }

    #[test]
    fn min_guard_hash_matches_server() {
        let expected: B256 =
            "0x9903897e51baa96a5ea51b4c194d3e0c6bcf20947cce9fd646dfb4bf754c8d28"
                .parse()
                .unwrap();
        assert_eq!(hash_leaf(&B256::ZERO, &B256::ZERO, 1), expected);
    }

    #[test]
    fn max_guard_hash_matches_server() {
        let expected: B256 =
            "0xb35299e7564e05e335094c02064bccf83d58745b417874b1fee3f523ec2007a9"
                .parse()
                .unwrap();
        assert_eq!(
            hash_leaf(&B256::repeat_byte(0xff), &B256::ZERO, 1),
            expected
        );
    }

    /// Dense reference: compute the root of a small tree by hashing every
    /// position up from the leaves, padding with empty subtrees.
    fn dense_root(leaves: &[(u64, TreeLeaf)], leaf_count: u64) -> B256 {
        let empty = empty_subtree_hashes_vec();
        let mut level: std::collections::HashMap<u64, B256> = leaves
            .iter()
            .map(|(i, l)| (*i, hash_leaf(&l.key, &l.value, l.next_index)))
            .collect();
        let mut width = leaf_count;
        for depth in 0..TREE_DEPTH {
            let mut next: std::collections::HashMap<u64, B256> = std::collections::HashMap::new();
            let next_width = width.div_ceil(2);
            for i in 0..next_width {
                let l = level.get(&(2 * i)).copied().unwrap_or(empty[depth as usize]);
                let r = level.get(&(2 * i + 1)).copied().unwrap_or(empty[depth as usize]);
                next.insert(i, blake2s_compress(&l, &r));
            }
            level = next;
            width = next_width;
        }
        level[&0]
    }

    /// Regression: the new-root computation in `apply()` must be correct for
    /// inserts whose sibling path was not visited by the old-root traversal —
    /// WITHOUT any trusted `expected_root_after`.
    ///
    /// Old tree (leaf_count = 5): MIN(0) -> data k2(2) -> k3(3) -> k4(4) -> MAX(1).
    /// Touched set: leaf 0 only (predecessor of the new key). Insert K with
    /// k0 < K < k2 at index 5. The new leaf's depth-0 sibling is leaf 4, which
    /// the old traversal never consumed.
    #[test]
    fn apply_insert_without_trusted_root_is_correct() {
        let k = |b: u8| B256::repeat_byte(b);
        let v = |b: u8| B256::repeat_byte(b);

        let leaf0 = TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
        let leaf1 = TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
        let leaf2 = TreeLeaf { key: k(0x20), value: v(0xa2), next_index: 3 };
        let leaf3 = TreeLeaf { key: k(0x30), value: v(0xa3), next_index: 4 };
        let leaf4 = TreeLeaf { key: k(0x40), value: v(0xa4), next_index: 1 };
        let old_leaves = vec![
            (0u64, leaf0.clone()),
            (1u64, leaf1.clone()),
            (2u64, leaf2.clone()),
            (3u64, leaf3.clone()),
            (4u64, leaf4.clone()),
        ];
        let old_root = dense_root(&old_leaves, 5);

        // New key between MIN and k2 -> predecessor is leaf 0, insert at index 5.
        let new_key = k(0x10);
        let new_value = v(0xb5);
        let leaf0_after = TreeLeaf { next_index: 5, ..leaf0.clone() };
        let leaf5 = TreeLeaf { key: new_key, value: new_value, next_index: 2 };
        let mut new_leaves = old_leaves.clone();
        new_leaves[0] = (0, leaf0_after);
        new_leaves.push((5, leaf5));
        let correct_new_root = dense_root(&new_leaves, 6);

        // Witness as the guest receives it: only leaf 0 in the touched set.
        // Old-traversal siblings for {0} at count 5:
        //   d0: sibling = leaf 1 hash; d1: node over leaves 2..3; d2: node over leaves 4..7.
        let h = |l: &TreeLeaf| hash_leaf(&l.key, &l.value, l.next_index);
        let empty = empty_subtree_hashes_vec();
        let sib_d2 = blake2s_compress(&blake2s_compress(&h(&leaf4), &empty[0]), &empty[1]);

        // Without an anchor for the ridge subtree (leaf 4's region), the
        // new-root pass must refuse rather than fall back to anything trusted.
        // Successor of the insert is leaf 2, which must be in the witness for
        // the ordering check, so include it; leaf 4's region stays uncovered.
        // Witness set {0, 2}: d0 siblings: leaf1 (for 0), leaf3 (for 2);
        // d1: nodes 0 and 1 both computed -> pair; d2: node over leaves 4..7.
        let update_no_anchor = BatchTreeUpdate {
            operations: vec![WriteOp::Insert { prev_index: 0 }],
            entries: vec![(new_key, new_value)],
            sorted_leaves: vec![(0, leaf0.clone()), (2, leaf2.clone())],
            intermediate_hashes: vec![h(&leaf1), h(&leaf3), sib_d2],
            leaf_count_before: 5,
        };
        let result = std::panic::catch_unwind(|| update_no_anchor.apply(&old_root));
        assert!(
            result.is_err(),
            "new-root pass must hard-fail on an unauthenticated sibling, not guess or trust"
        );

        // With leaf 4 included as an anchor, the new root must be computed
        // correctly — from authenticated data only.
        // Witness set {0, 2, 4}: d0 siblings: leaf1 (for 0), leaf3 (for 2),
        // empty (leaf 4 is last); d1: nodes 0,1 pair; node 2 last -> empty;
        // d2: nodes 0,1 pair; beyond: empty.
        let update_with_anchor = BatchTreeUpdate {
            operations: vec![WriteOp::Insert { prev_index: 0 }],
            entries: vec![(new_key, new_value)],
            sorted_leaves: vec![(0, leaf0), (2, leaf2), (4, leaf4)],
            intermediate_hashes: vec![h(&leaf1), h(&leaf3)],
            leaf_count_before: 5,
        };
        let (computed_root, new_count) = update_with_anchor.apply(&old_root);
        assert_eq!(new_count, 6);
        assert_eq!(
            computed_root, correct_new_root,
            "independent new-root computation must match the dense reference"
        );
    }

    /// Two chained inserts: the second insert's predecessor is the first new
    /// leaf; new leaves pair with each other in the new-root pass.
    #[test]
    fn apply_chained_inserts_is_correct() {
        let k = |b: u8| B256::repeat_byte(b);
        let leaf0 = TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
        let leaf1 = TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
        let leaf2 = TreeLeaf { key: k(0x40), value: k(0xa2), next_index: 1 };
        let old_leaves = vec![(0u64, leaf0.clone()), (1u64, leaf1.clone()), (2u64, leaf2.clone())];
        let old_root = dense_root(&old_leaves, 3);

        // Insert 0x10 (prev = leaf 0), then 0x20 (prev = the new leaf 3).
        let leaf3 = TreeLeaf { key: k(0x10), value: k(0xb3), next_index: 4 };
        let leaf4 = TreeLeaf { key: k(0x20), value: k(0xb4), next_index: 2 };
        let leaf0_after = TreeLeaf { next_index: 3, ..leaf0.clone() };
        let new_leaves = vec![
            (0u64, leaf0_after),
            (1u64, leaf1.clone()),
            (2u64, leaf2.clone()),
            (3u64, leaf3),
            (4u64, leaf4),
        ];
        let correct_new_root = dense_root(&new_leaves, 5);

        let h = |l: &TreeLeaf| hash_leaf(&l.key, &l.value, l.next_index);
        // Witness {0, 2}: d0 siblings: leaf1 (for 0), empty (leaf2 is last);
        // d1: node0 computed, node1 (from leaf2) computed -> pair. Beyond: empty.
        let update = BatchTreeUpdate {
            operations: vec![
                WriteOp::Insert { prev_index: 0 },
                WriteOp::Insert { prev_index: 3 },
            ],
            entries: vec![(k(0x10), k(0xb3)), (k(0x20), k(0xb4))],
            sorted_leaves: vec![(0, leaf0), (2, leaf2)],
            intermediate_hashes: vec![h(&leaf1)],
            leaf_count_before: 3,
        };
        let (computed_root, new_count) = update.apply(&old_root);
        assert_eq!(new_count, 5);
        assert_eq!(computed_root, correct_new_root);
    }

    /// An insert whose predecessor does not bracket the key must be rejected.
    #[test]
    fn apply_rejects_insert_ordering_violation() {
        let k = |b: u8| B256::repeat_byte(b);
        let leaf0 = TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
        let leaf1 = TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
        let leaf2 = TreeLeaf { key: k(0x40), value: k(0xa2), next_index: 1 };
        let old_leaves = vec![(0u64, leaf0.clone()), (1u64, leaf1.clone()), (2u64, leaf2.clone())];
        let old_root = dense_root(&old_leaves, 3);

        let h = |l: &TreeLeaf| hash_leaf(&l.key, &l.value, l.next_index);
        // Key 0x50 belongs after leaf2 (0x40), but the witness claims leaf 0
        // (key 0) is the predecessor — succeeding leaf 2 (0x40) < 0x50.
        let update = BatchTreeUpdate {
            operations: vec![WriteOp::Insert { prev_index: 0 }],
            entries: vec![(k(0x50), k(0xb3))],
            sorted_leaves: vec![(0, leaf0), (2, leaf2)],
            intermediate_hashes: vec![h(&leaf1)],
            leaf_count_before: 3,
        };
        let result = std::panic::catch_unwind(|| update.apply(&old_root));
        assert!(result.is_err(), "mis-bracketed insert must be rejected");
    }

    // =================== Streaming tree-update A/B ===================
    //
    // The streaming `apply` must reproduce the reference two-pass `apply_reference`
    // AND an independent dense-root oracle, bit-for-bit, across updates, inserts,
    // and mixes, at many depths — with dense witnesses (no intermediate hashes)
    // and with sparse witnesses (real intermediate hashes exercising the
    // off-path-sibling consumption path).

    /// B256 whose low 8 bytes hold `x` big-endian (so ordering matches `x`, and
    /// all keys stay strictly between the MIN(0) and MAX(0xff..) guards).
    fn key_of(x: u64) -> B256 {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&x.to_be_bytes());
        B256::from(b)
    }

    /// Dense old tree: MIN/MAX guards + `l` data leaves, keys `(i+1)*1_000_000`
    /// (1e6 gaps leave room for inserts). Returns (leaves by index, leaf_count,
    /// old_root).
    fn build_old_dense(l: u64) -> (Vec<(u64, TreeLeaf)>, u64, B256) {
        let mut leaves: Vec<(u64, TreeLeaf)> = Vec::new();
        leaves.push((
            0,
            TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: if l > 0 { 2 } else { 1 } },
        ));
        leaves.push((
            1,
            TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 },
        ));
        for i in 0..l {
            let idx = 2 + i;
            let next = if i + 1 < l { 2 + i + 1 } else { 1 };
            leaves.push((
                idx,
                TreeLeaf { key: key_of((i + 1) * 1_000_000), value: key_of(1000 + i), next_index: next },
            ));
        }
        let leaf_count = l + 2;
        let root = dense_root(&leaves, leaf_count);
        (leaves, leaf_count, root)
    }

    /// Dense full internal-node levels (level 0 = leaf hashes over a contiguous
    /// 0..leaf_count index space), for emitting sparse-witness siblings.
    fn full_levels(leaves: &[(u64, TreeLeaf)], leaf_count: u64) -> Vec<Vec<B256>> {
        let empty = empty_subtree_hashes_vec();
        let mut lvl0 = vec![B256::ZERO; leaf_count as usize];
        for (i, l) in leaves {
            lvl0[*i as usize] = hash_leaf(&l.key, &l.value, l.next_index);
        }
        let mut levels = vec![lvl0];
        while levels.last().unwrap().len() > 1 {
            let d = levels.len() - 1;
            let cur = levels.last().unwrap();
            let up: Vec<B256> = (0..cur.len().div_ceil(2))
                .map(|i| {
                    let l = cur[2 * i];
                    let r = cur.get(2 * i + 1).copied().unwrap_or(empty[d]);
                    blake2s_compress(&l, &r)
                })
                .collect();
            levels.push(up);
        }
        levels
    }

    /// Emit the off-path sibling hashes for a sparse witness over `touched`
    /// (sorted ascending touched indices), in the exact traversal order the old
    /// root reconstruction consumes them. Mirrors `zip_and_record`'s decisions.
    fn sparse_intermediates(
        levels: &[Vec<B256>],
        touched: &[u64],
        leaf_count: u64,
    ) -> Vec<B256> {
        let mut out = Vec::new();
        let mut nodes: Vec<u64> = touched.to_vec();
        let mut last_idx = leaf_count - 1;
        for depth in 0..TREE_DEPTH as usize {
            let mut i = 0;
            let mut next = Vec::new();
            while i < nodes.len() {
                let cur = nodes[i];
                if cur % 2 == 1 {
                    i += 1;
                    out.push(levels[depth][(cur - 1) as usize]);
                } else if i + 1 < nodes.len() && nodes[i + 1] == cur + 1 {
                    i += 2;
                } else {
                    i += 1;
                    if cur != last_idx {
                        out.push(levels[depth][(cur + 1) as usize]);
                    }
                }
                next.push(cur / 2);
            }
            nodes = next;
            last_idx /= 2;
        }
        out
    }

    /// Assert `apply == apply_reference == dense oracle` for a dense witness
    /// (all leaves present, no intermediate hashes) with `update_stride` updates
    /// and `insert_stride` inserts over an `l`-leaf tree. Update targets and
    /// insert predecessors are disjoint so the independent oracle is simple.
    fn ab_dense_case(l: u64, update_stride: u64, insert_stride: u64) {
        let (old_leaves, leaf_count, root) = build_old_dense(l);

        let mut expected = old_leaves.clone();
        let mut pos: std::collections::HashMap<u64, usize> =
            expected.iter().enumerate().map(|(p, (i, _))| (*i, p)).collect();

        let mut operations = Vec::new();
        let mut entries = Vec::new();
        let mut updated: std::collections::HashSet<u64> = Default::default();

        if update_stride > 0 {
            let mut i = 0;
            while i < l {
                let idx = 2 + i;
                let new_val = key_of(9_000_000 + i);
                operations.push(WriteOp::Update { index: idx });
                entries.push((old_leaves[idx as usize].1.key, new_val));
                expected[pos[&idx]].1.value = new_val;
                updated.insert(idx);
                i += update_stride;
            }
        }

        let mut next_index = leaf_count;
        if insert_stride > 0 && l > 0 {
            let mut i = 0;
            while i < l {
                let pred_idx = 2 + i;
                if !updated.contains(&pred_idx) {
                    let new_key = key_of((i + 1) * 1_000_000 + 500_000);
                    let new_val = key_of(8_000_000 + i);
                    let this_index = next_index;
                    next_index += 1;
                    operations.push(WriteOp::Insert { prev_index: pred_idx });
                    entries.push((new_key, new_val));
                    let old_next = expected[pos[&pred_idx]].1.next_index;
                    expected[pos[&pred_idx]].1.next_index = this_index;
                    let new_pos = expected.len();
                    expected.push((this_index, TreeLeaf { key: new_key, value: new_val, next_index: old_next }));
                    pos.insert(this_index, new_pos);
                }
                i += insert_stride;
            }
        }

        let update = BatchTreeUpdate {
            operations,
            entries,
            sorted_leaves: old_leaves.clone(),
            intermediate_hashes: vec![],
            leaf_count_before: leaf_count,
        };

        let (r_new, c_new) = update.apply(&root);
        let (r_ref, c_ref) = update.apply_reference(&root);
        assert_eq!(r_new, r_ref, "dense apply vs reference root (l={l})");
        assert_eq!(c_new, c_ref, "dense apply vs reference count (l={l})");

        expected.sort_by_key(|(i, _)| *i);
        let oracle = dense_root(&expected, next_index);
        assert_eq!(r_new, oracle, "dense apply vs oracle root (l={l})");
        assert_eq!(c_new, next_index, "dense apply count (l={l})");
    }

    #[test]
    fn ab_dense_updates_inserts_mixed() {
        // (l, update_stride, insert_stride) across many shapes/depths.
        ab_dense_case(0, 0, 0); // empty tree, no ops
        ab_dense_case(1, 1, 0); // single update
        ab_dense_case(1, 0, 1); // single insert
        ab_dense_case(3, 1, 0); // all updates
        ab_dense_case(3, 0, 1); // all inserts
        ab_dense_case(7, 2, 3); // mixed
        ab_dense_case(15, 3, 4); // mixed, depth ~4
        ab_dense_case(31, 5, 7); // mixed, depth ~5
        ab_dense_case(100, 7, 11); // mixed, depth ~7
        ab_dense_case(500, 0, 13); // insert-heavy, depth ~9
        ab_dense_case(1000, 50, 97); // mixed, depth ~10
    }

    /// Sparse update-only witnesses: only the updated leaves are in
    /// `sorted_leaves`, and `intermediate_hashes` carries the off-path siblings.
    /// This exercises the streaming `apply`'s intermediate-consumption path and
    /// compares it against the reference two-pass and the dense oracle.
    fn ab_sparse_updates_case(l: u64, stride: u64) {
        let (old_leaves, leaf_count, root) = build_old_dense(l);
        let levels = full_levels(&old_leaves, leaf_count);

        // Touched (updated) data leaves.
        let mut touched: Vec<u64> = Vec::new();
        let mut i = 0;
        while i < l {
            touched.push(2 + i);
            i += stride.max(1);
        }
        touched.sort_unstable();

        let sorted_leaves: Vec<(u64, TreeLeaf)> = touched
            .iter()
            .map(|&idx| (idx, old_leaves[idx as usize].1.clone()))
            .collect();
        let intermediate_hashes = sparse_intermediates(&levels, &touched, leaf_count);

        let mut operations = Vec::new();
        let mut entries = Vec::new();
        let mut expected = old_leaves.clone();
        for (n, &idx) in touched.iter().enumerate() {
            let new_val = key_of(7_000_000 + n as u64);
            operations.push(WriteOp::Update { index: idx });
            entries.push((old_leaves[idx as usize].1.key, new_val));
            expected[idx as usize].1.value = new_val;
        }

        let update = BatchTreeUpdate {
            operations,
            entries,
            sorted_leaves,
            intermediate_hashes,
            leaf_count_before: leaf_count,
        };

        let (r_new, c_new) = update.apply(&root);
        let (r_ref, c_ref) = update.apply_reference(&root);
        assert_eq!(r_new, r_ref, "sparse apply vs reference root (l={l})");
        assert_eq!(c_new, c_ref, "sparse apply vs reference count (l={l})");

        let oracle = dense_root(&expected, leaf_count);
        assert_eq!(r_new, oracle, "sparse apply vs oracle root (l={l})");
        assert_eq!(c_new, leaf_count, "sparse apply count (l={l})");
    }

    #[test]
    fn ab_sparse_update_only_intermediate_hashes() {
        ab_sparse_updates_case(3, 1);
        ab_sparse_updates_case(7, 2);
        ab_sparse_updates_case(15, 3);
        ab_sparse_updates_case(31, 4);
        ab_sparse_updates_case(100, 9);
        ab_sparse_updates_case(255, 17);
        ab_sparse_updates_case(1000, 137);
    }

    /// A/B the two hand-built sparse-INSERT witnesses (with anchors + real
    /// intermediate hashes) against the reference two-pass.
    #[test]
    fn ab_sparse_inserts_against_reference() {
        let h = |l: &TreeLeaf| hash_leaf(&l.key, &l.value, l.next_index);

        // Case 1: single insert with an anchor leaf (from
        // `apply_insert_without_trusted_root_is_correct`).
        {
            let leaf0 = TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
            let leaf1 = TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
            let leaf2 = TreeLeaf { key: B256::repeat_byte(0x20), value: B256::repeat_byte(0xa2), next_index: 3 };
            let leaf3 = TreeLeaf { key: B256::repeat_byte(0x30), value: B256::repeat_byte(0xa3), next_index: 4 };
            let leaf4 = TreeLeaf { key: B256::repeat_byte(0x40), value: B256::repeat_byte(0xa4), next_index: 1 };
            let old_leaves = vec![
                (0u64, leaf0.clone()),
                (1u64, leaf1.clone()),
                (2u64, leaf2.clone()),
                (3u64, leaf3.clone()),
                (4u64, leaf4.clone()),
            ];
            let old_root = dense_root(&old_leaves, 5);
            let update = BatchTreeUpdate {
                operations: vec![WriteOp::Insert { prev_index: 0 }],
                entries: vec![(B256::repeat_byte(0x10), B256::repeat_byte(0xb5))],
                sorted_leaves: vec![(0, leaf0), (2, leaf2), (4, leaf4)],
                intermediate_hashes: vec![h(&leaf1), h(&leaf3)],
                leaf_count_before: 5,
            };
            assert_eq!(update.apply(&old_root), update.apply_reference(&old_root));
        }

        // Case 2: two chained inserts (from `apply_chained_inserts_is_correct`).
        {
            let leaf0 = TreeLeaf { key: B256::ZERO, value: B256::ZERO, next_index: 2 };
            let leaf1 = TreeLeaf { key: B256::repeat_byte(0xff), value: B256::ZERO, next_index: 1 };
            let leaf2 = TreeLeaf { key: B256::repeat_byte(0x40), value: B256::repeat_byte(0xa2), next_index: 1 };
            let old_leaves = vec![(0u64, leaf0.clone()), (1u64, leaf1.clone()), (2u64, leaf2.clone())];
            let old_root = dense_root(&old_leaves, 3);
            let update = BatchTreeUpdate {
                operations: vec![
                    WriteOp::Insert { prev_index: 0 },
                    WriteOp::Insert { prev_index: 3 },
                ],
                entries: vec![
                    (B256::repeat_byte(0x10), B256::repeat_byte(0xb3)),
                    (B256::repeat_byte(0x20), B256::repeat_byte(0xb4)),
                ],
                sorted_leaves: vec![(0, leaf0), (2, leaf2)],
                intermediate_hashes: vec![h(&leaf1)],
                leaf_count_before: 3,
            };
            assert_eq!(update.apply(&old_root), update.apply_reference(&old_root));
        }
    }
}
