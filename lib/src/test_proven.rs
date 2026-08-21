//! Test that the proven execution path works end-to-end with real merkle proofs.

#[cfg(test)]
mod tests {
    use crate::executor;
    use crate::merkle::*;
    use crate::types::*;
    use alloy_primitives::{Address, B256, U256};

    /// Build a minimal merkle tree with MIN_GUARD (idx 0), MAX_GUARD (idx 1),
    /// and one data leaf (idx 2). Returns (root_hash, leaf_count, sibling_hashes_for_leaf2).
    fn build_minimal_tree(data_key: &B256, data_value: &B256) -> (B256, u64, Vec<B256>) {
        let empty = empty_subtree_hashes_vec();

        // Leaf 0: MIN_GUARD (key=0, value=0, next_index=2 -> points to data leaf)
        let leaf0 = hash_leaf(&B256::ZERO, &B256::ZERO, 2);
        // Leaf 1: MAX_GUARD (key=0xff..ff, value=0, next_index=1 -> self-loop)
        let leaf1 = hash_leaf(&B256::repeat_byte(0xff), &B256::ZERO, 1);
        // Leaf 2: data leaf (key=data_key, value=data_value, next_index=1 -> MAX_GUARD)
        let leaf2 = hash_leaf(data_key, data_value, 1);

        let leaf_count: u64 = 3;

        // Build the tree bottom-up. We need to compute the root and collect siblings for leaf 2.
        // Tree structure at depth 0 (leaves):
        //   idx 0: leaf0, idx 1: leaf1, idx 2: leaf2, idx 3...: empty
        //
        // For proof of leaf at index 2:
        //   depth 0: sibling is idx 3 (empty[0])
        //   depth 1: sibling is hash(leaf0, leaf1) at idx 0 on level 1
        //   depth 2..63: empty subtree hashes

        // Level 0 -> Level 1
        let node_01 = blake2s_compress_pub(&leaf0, &leaf1);  // index 0 on level 1
        let node_23 = blake2s_compress_pub(&leaf2, &empty[0]); // index 1 on level 1

        // Level 1 -> Level 2
        let node_0123 = blake2s_compress_pub(&node_01, &node_23); // index 0 on level 2

        // Level 2..63: pair with empty subtrees
        let mut current = node_0123;
        for d in 2..TREE_DEPTH {
            current = blake2s_compress_pub(&current, &empty[d as usize]);
        }
        let root = current;

        // Siblings for leaf at index 2:
        // depth 0: sibling at idx 3 = empty[0]
        // depth 1: sibling at idx 0 = node_01
        // depth 2..63: empty[depth]
        let mut siblings = vec![empty[0], node_01];
        for d in 2..TREE_DEPTH {
            siblings.push(empty[d as usize]);
        }

        (root, leaf_count, siblings)
    }

    // Expose the compress function for test
    fn blake2s_compress_pub(lhs: &B256, rhs: &B256) -> B256 {
        use blake2::Digest;
        let mut h = blake2::Blake2s256::new();
        h.update(lhs.as_slice());
        h.update(rhs.as_slice());
        B256::from_slice(&h.finalize())
    }

    fn empty_subtree_hashes_vec() -> Vec<B256> {
        let mut hashes = vec![empty_subtree_hash(0)];
        for d in 1..=TREE_DEPTH {
            hashes.push(empty_subtree_hash(d));
        }
        hashes
    }

    /// Blake2s commitment of an all-zero 256-entry pre-state block-hash ring —
    /// the correct `block_hashes_blake_before` for a batch whose first block
    /// carries no witnessed history (empty `block_hashes`). Matches what the
    /// executor now reconstructs and asserts for that case.
    fn empty_ring_blake() -> B256 {
        crate::commitment::block_hashes_blake(&[B256::ZERO; 255], &B256::ZERO)
    }

    /// Encode account properties into 124-byte blob.
    fn encode_account_props(nonce: u64, balance: U256) -> Vec<u8> {
        let mut data = vec![0u8; 124];
        // bytes 0-7: versioning (all zero = not deployed)
        // bytes 8-15: nonce BE
        data[8..16].copy_from_slice(&nonce.to_be_bytes());
        // bytes 16-47: balance BE
        data[16..48].copy_from_slice(&balance.to_be_bytes::<32>());
        // bytes 48-79: bytecode_hash (zero = no code)
        // bytes 80-83: unpadded_code_len (zero)
        // bytes 84-87: artifacts_len (zero)
        // bytes 88-119: observable_bytecode_hash (zero)
        // bytes 120-123: observable_bytecode_len (zero)
        data
    }

    /// A one-block batch whose single L1 transaction is force-failed, so the
    /// only merkle proof it needs is the sender's account-properties leaf. The
    /// caller picks the spec and the protocol minor, which is what makes the
    /// batch usable for the version-gated commitment layouts.
    fn minimal_force_fail_batch(spec_id: u8, protocol_version_minor: u32) -> BatchInput {
        // Setup: a sender with 10 ETH, nonce 0
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002"
            .parse()
            .unwrap();

        // Encode sender account properties
        let sender_balance = U256::from(10_000_000_000_000_000_000u128); // 10 ETH
        let sender_props = encode_account_props(0, sender_balance);
        let sender_props_hash = AccountProperties::hash(&sender_props);

        // Compute the flat key for the sender's account properties
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        // Build a minimal merkle tree with this one data leaf
        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        // Verify our proof works
        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2, // data leaf is at index 2
            value: sender_props_hash,
            next_index: 1, // points to MAX_GUARD
            siblings: siblings.clone(),
        });
        let (recovered_root, value) = proof.verify(&sender_flat_key).unwrap();
        assert_eq!(recovered_root, tree_root, "proof should recover tree root");
        assert_eq!(value.unwrap(), sender_props_hash, "proof should return correct value");

        // Build proper ABI-encoded L2CanonicalTransaction for the L1 tx.
        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20; // outer offset
            abi[32 + 31] = 0x7f; // txType
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice()); // from
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice()); // to
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes()); // gasLimit
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes()); // maxFeePerGas
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice()); // reserved[1]=refund
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        // Now build a BatchInput with this proof
        BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id,
            protocol_version_minor,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: leaf_count,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: empty_ring_blake(),
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
                account_preimages_after: vec![],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
                interop_proofs: None,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender,  // use sender as coinbase so no extra proof needed
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                // The merkle proof for the sender's account properties
                storage_proofs: vec![(sender_flat_key, proof)],
                // Account preimage for decoding
                account_preimages: vec![(sender, sender_props)],
                // Use force_fail to avoid full execution (which would access
                // accounts we don't have proofs for in this minimal tree).
                // This test focuses on verifying proof + preimage decoding.
                transactions: vec![TxInput {
                    chain_id: Some(270),
                    gas_used_override: Some(0),
                    force_fail: true,
                    auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![L2ToL1LogEntry {
                    l2_shard_id: 0,
                    is_service: true,
                    tx_number_in_block: 0,
                    sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                    key: l1_tx_hash,  // tx_hash from the ABI encoding
                    value: B256::ZERO,  // force_fail → success=false → value=0
                }],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        }
    }

    #[test]
    fn test_proven_path_with_real_merkle_proofs() {
        let batch_input = minimal_force_fail_batch(1, 30); // AtlasV2, protocol v30

        // Run the proven execution path
        let (output, commitment) = executor::execute_and_commit(&batch_input);

        // Verify execution produced results
        assert_eq!(output.block_results.len(), 1);
        let br = &output.block_results[0];
        assert!(!br.tx_results.is_empty(), "should have tx results");

        let tx = &br.tx_results[0];
        assert!(!tx.success, "force_fail tx should fail");
        println!("tx[0]: success={}, gas_used={}", tx.success, tx.gas_used);

        // Commitment should be non-zero
        assert_ne!(commitment, B256::ZERO, "commitment should be non-zero");
        println!("BatchPublicInput commitment: {commitment}");
    }

    /// A batch on a spec before AtlasV4 commits the three-word public input
    /// `keccak256(state_before ‖ state_after ‖ batch_output)`, which is what
    /// released native computes on the v30 and v31 lines. A fourth word would
    /// commit a value the first prover never produces, so L1 could not gate the
    /// two lanes against each other.
    #[test]
    fn pre_atlas_v4_commits_the_three_word_public_input() {
        // AtlasV1 and AtlasV2 (protocol v30) plus AtlasV3 (protocol v31).
        let batches = [
            minimal_force_fail_batch(0, 30),
            minimal_force_fail_batch(1, 30),
            honest_transfer_batch().0,
        ];
        for batch_input in batches {
            let spec_id = batch_input.spec_id;
            let (_output, commitment, state_before, state_after, batch_output) =
                executor::execute_and_commit_debug(&batch_input);

            assert_eq!(
                commitment,
                crate::commitment::batch_public_input_hash(
                    &state_before,
                    &state_after,
                    None,
                    &batch_output,
                ),
                "spec_id {spec_id} must commit three words",
            );

            // The AtlasV4 four-word form of the same batch is a different value,
            // so the gate is doing work rather than agreeing by accident.
            let chain_config_hash = crate::commitment::chain_config_hash(
                batch_input.chain_id,
                batch_input.batch_meta.fri_proof_verification_enabled,
                batch_input.batch_meta.max_tx_gas_limit,
            );
            assert_ne!(
                commitment,
                crate::commitment::batch_public_input_hash(
                    &state_before,
                    &state_after,
                    Some(&chain_config_hash),
                    &batch_output,
                ),
            );
        }
    }

    #[test]
    fn export_proven_input_for_emulator() {
        // Same setup as test_proven_path_with_real_merkle_proofs
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002"
            .parse()
            .unwrap();

        let sender_balance = U256::from(10_000_000_000_000_000_000u128);
        let sender_props = encode_account_props(0, sender_balance);
        let sender_props_hash = AccountProperties::hash(&sender_props);
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2,
            value: sender_props_hash,
            next_index: 1,
            siblings,
        });

        // Build a proper ABI-encoded L2CanonicalTransaction so the batch actually
        // executes. (The previous dummy 11-byte abi_encoded panicked in tx.rs's ABI
        // decoder — it was not a runnable batch.) Mirrors the force_fail path in
        // test_proven_path_with_real_merkle_proofs.
        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20; // outer offset
            abi[32 + 31] = 0x7f; // txType
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice()); // from
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice()); // to
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes()); // gasLimit
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes()); // maxFeePerGas
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice()); // reserved[1]=refund
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        let batch_input = BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: leaf_count,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: empty_ring_blake(),
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
                account_preimages_after: vec![],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
                interop_proofs: None,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender, // coinbase = sender so no extra account proof is needed
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(sender_flat_key, proof)],
                account_preimages: vec![(sender, sender_props)],
                transactions: vec![TxInput {
                    chain_id: Some(270),
                    gas_used_override: Some(0),
                    force_fail: true,
                    auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![L2ToL1LogEntry {
                    l2_shard_id: 0,
                    is_service: true,
                    tx_number_in_block: 0,
                    sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                    key: l1_tx_hash,
                    value: B256::ZERO,
                }],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // Serialize in ZiSK stdin format
        let data = crate::wire::encode(&batch_input).unwrap();
        let len = data.len() as u64;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&data);
        let total = 8 + data.len();
        let padding = (8 - (total % 8)) % 8;
        buf.extend(std::iter::repeat(0u8).take(padding));

        std::fs::write("/tmp/proven_input.bin", &buf).unwrap();
        println!("Wrote proven input to /tmp/proven_input.bin ({} bytes)", buf.len());
    }

    /// Compute the native reference commitment for the exact bytes in
    /// /tmp/proven_input.bin — the value the ZiSK guest must reproduce.
    #[test]
    #[ignore = "manual helper: run export_proven_input_for_emulator first"]
    fn print_input_bin_commitment() {
        let data = std::fs::read("/tmp/proven_input.bin").unwrap();
        let len = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let bi: BatchInput = crate::wire::decode(&data[8..8 + len]).unwrap();
        let (_o, c) = crate::executor::execute_and_commit(&bi);
        println!("INPUT_BIN_COMMITMENT: {c}");
    }

    #[test]
    fn test_proof_verification_catches_wrong_value() {
        let sender: Address = "0x1000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let sender_addr_bytes: [u8; 20] = sender.into_array();
        let sender_flat_key = derive_account_properties_key(&sender_addr_bytes);

        // Real account: 10 ETH
        let real_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let real_hash = AccountProperties::hash(&real_props);

        // Build tree with real value
        let (tree_root, _leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &real_hash);

        // Try to use a FAKE preimage (1000 ETH instead of 10 ETH)
        let fake_props = encode_account_props(0, U256::from(1_000_000_000_000_000_000_000u128));

        // The proof is valid for the real_hash, but the fake preimage has a different hash
        let fake_hash = AccountProperties::hash(&fake_props);
        assert_ne!(real_hash, fake_hash, "hashes should differ");

        // Constructing a BatchInput with mismatched preimage should be caught
        // by build_proven_db which asserts preimage_hash == proven_value
        let proof = StorageProof::Existing(SlotProofEntry {
            index: 2,
            value: real_hash, // tree has real_hash
            next_index: 1,
            siblings,
        });

        // Verify the proof works with the real key
        let (root, _) = proof.verify(&sender_flat_key).unwrap();
        assert_eq!(root, tree_root);

        // Now build BatchInput with the fake preimage — this should panic
        let batch_input = BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: tree_root,
                leaf_count_before: 3,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
                account_preimages_after: vec![],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
                interop_proofs: None,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: Address::ZERO,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(sender_flat_key, proof)],
                account_preimages: vec![(sender, fake_props)], // FAKE
                transactions: vec![],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // This should panic because preimage hash != proven value
        let result = std::panic::catch_unwind(|| {
            executor::execute_and_commit(&batch_input);
        });
        assert!(result.is_err(), "should panic on fake preimage");
        println!("Correctly caught fake account preimage!");
    }

    /// Dense tree over MIN/MAX guards + data leaves with a correct sorted
    /// linked list. Returns (root, all leaves by index, per-leaf sibling paths).
    fn build_dense_tree(
        data: &[(B256, B256)],
    ) -> (B256, Vec<(u64, TreeLeaf)>, Vec<Vec<B256>>) {
        // Indices: 0 = MIN guard, 1 = MAX guard, 2.. = data in given order.
        let mut recs: Vec<(u64, B256, B256)> = vec![
            (0, B256::ZERO, B256::ZERO),
            (1, B256::repeat_byte(0xff), B256::ZERO),
        ];
        for (i, (k, v)) in data.iter().enumerate() {
            recs.push((2 + i as u64, *k, *v));
        }
        // next pointers follow key order; MAX guard self-loops.
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

        // Dense levels bottom-up.
        let mut levels: Vec<Vec<B256>> = vec![leaves
            .iter()
            .map(|(_, l)| hash_leaf(&l.key, &l.value, l.next_index))
            .collect()];
        while levels.last().unwrap().len() > 1 {
            let d = levels.len() - 1;
            let cur = levels.last().unwrap();
            let next_level: Vec<B256> = (0..cur.len().div_ceil(2))
                .map(|i| {
                    let l = cur[2 * i];
                    let r = cur.get(2 * i + 1).copied().unwrap_or(empty_subtree_hash(d as u8));
                    blake2s_compress_pub(&l, &r)
                })
                .collect();
            levels.push(next_level);
        }
        let mut root = levels.last().unwrap()[0];
        for d in (levels.len() - 1)..(TREE_DEPTH as usize) {
            root = blake2s_compress_pub(&root, &empty_subtree_hash(d as u8));
        }

        let siblings: Vec<Vec<B256>> = (0..leaves.len() as u64)
            .map(|i| {
                (0..TREE_DEPTH as usize)
                    .map(|d| {
                        let pos = ((i >> d) ^ 1) as usize;
                        levels
                            .get(d)
                            .and_then(|lvl| lvl.get(pos).copied())
                            .unwrap_or(empty_subtree_hash(d as u8))
                    })
                    .collect()
            })
            .collect();
        (root, leaves, siblings)
    }

    /// Apply a `BatchTreeUpdate` to its pre-state leaf set and return the
    /// post-state data leaves (index >= 2) in index order. Mirrors the guest's
    /// `apply_writes` index assignment: updates keep their index; inserts take
    /// dense indices from `leaf_count_before`.
    fn post_state_data(update: &BatchTreeUpdate) -> Vec<(B256, B256)> {
        use std::collections::BTreeMap;
        let mut by_index: BTreeMap<u64, (B256, B256)> = update
            .sorted_leaves
            .iter()
            .map(|(i, l)| (*i, (l.key, l.value)))
            .collect();
        let mut next_index = update.leaf_count_before;
        for (op, (key, val)) in update.operations.iter().zip(&update.entries) {
            match op {
                WriteOp::Update { index } => {
                    by_index.get_mut(index).expect("update target present").1 = *val;
                }
                WriteOp::Insert { .. } => {
                    by_index.insert(next_index, (*key, *val));
                    next_index += 1;
                }
            }
        }
        by_index
            .into_iter()
            .filter(|(i, _)| *i >= 2)
            .map(|(_, kv)| kv)
            .collect()
    }

    /// Interop slot keys (guest-visible flat keys) for a non-settlement chain.
    fn interop_slot_keys() -> (B256, B256, B256) {
        const SYSTEM_CONTEXT_ADDR: [u8; 20] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x0b,
        ];
        const MESSAGE_ROOT_ADDR: [u8; 20] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x05,
        ];
        let sl_key = derive_flat_storage_key(&SYSTEM_CONTEXT_ADDR, &B256::ZERO);
        let height_key = derive_flat_storage_key(&MESSAGE_ROOT_ADDR, &B256::with_last_byte(0x04));
        // nodes[0][0] slot = keccak256(keccak256(word(0x06))) (height 0).
        let base = crate::hash::keccak256(B256::with_last_byte(0x06).as_slice());
        let root_slot = crate::hash::keccak256(base.as_slice());
        let root_key = derive_flat_storage_key(&MESSAGE_ROOT_ADDR, &root_slot);
        (sl_key, height_key, root_key)
    }

    /// Build the three NonExisting interop slot proofs for a NON-settlement-layer
    /// v31 batch (derives `sl_chain_id` 0, `multichain_root` 0). All three are
    /// read at post-state, so every proof is built against the post-state tree
    /// rebuilt from the `tree_update`; its root equals the guest's
    /// `tree_root_after`.
    fn interop_proofs_nonsettlement(update: &BatchTreeUpdate) -> InteropSlotProofs {
        let (_post_root, post_leaves, post_sib) = build_dense_tree(&post_state_data(update));
        let (sl_key, height_key, root_key) = interop_slot_keys();
        InteropSlotProofs {
            sl_chain_id: non_existence_proof(&post_leaves, &post_sib, &sl_key),
            multichain_height: non_existence_proof(&post_leaves, &post_sib, &height_key),
            multichain_root: non_existence_proof(&post_leaves, &post_sib, &root_key),
        }
    }

    /// Production fee semantics: the operator (coinbase) is credited the FULL
    /// effective gas price per unit of gas used. Production zksync-os is built
    /// WITHOUT the `burn_base_fee` cargo feature (the server pins
    /// forward_system with `features = ["production", "no_print"]`), so there
    /// is no EIP-1559-style base-fee burn — see basic_bootloader
    /// transaction_flow/zk/mod.rs, non-burn branch of `gas_price_for_operator`.
    ///
    /// gas_price 10 vs base_fee 7 makes the two models distinguishable:
    /// full price credits 10/gas, mainnet burn semantics would credit 3/gas.
    /// A guest regression to burn semantics fails this test both ways.
    #[test]
    fn coinbase_reward_is_full_effective_gas_price() {
        use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
        use alloy_eips::eip2718::Encodable2718;
        use k256::ecdsa::SigningKey;

        // Deterministic sender key.
        let sk = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let pubkey = sk.verifying_key().to_encoded_point(false);
        let sender = Address::from_slice(
            &alloy_primitives::keccak256(&pubkey.as_bytes()[1..])[12..],
        );
        let coinbase: Address = "0x00000000000000000000000000000000c01badde".parse().unwrap();

        const GAS_PRICE: u64 = 10;
        const BASE_FEE: u64 = 7;
        const GAS_USED: u64 = 21_000;
        let sender_balance_before = U256::from(1_000_000_000_000_000_000u128);
        let coinbase_balance_before = U256::from(5u64);

        // Signed legacy self-transfer (value 0), gas_price 10.
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: GAS_PRICE as u128,
            gas_limit: 100_000,
            to: alloy_primitives::TxKind::Call(sender),
            value: U256::ZERO,
            input: Default::default(),
        };
        let sighash = tx.signature_hash();
        let (sig, recid) = sk.sign_prehash_recoverable(sighash.as_slice()).unwrap();
        let sig_bytes = sig.to_bytes();
        let signature = alloy_primitives::Signature::new(
            U256::from_be_slice(&sig_bytes[..32]),
            U256::from_be_slice(&sig_bytes[32..]),
            recid.is_y_odd(),
        );
        let envelope = TxEnvelope::Legacy(tx.into_signed(signature));
        let mut signed_bytes = Vec::new();
        envelope.encode_2718(&mut signed_bytes);

        // Pre-state tree: sender + coinbase as existing accounts.
        let sender_props = encode_account_props(0, sender_balance_before);
        let coinbase_props = encode_account_props(0, coinbase_balance_before);
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
        ]);

        let proof_for = |idx: u64| {
            let (_, leaf) = &leaves[idx as usize];
            StorageProof::Existing(SlotProofEntry {
                index: idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx as usize].clone(),
            })
        };

        // Build the batch for a given claimed after-state of the coinbase.
        let fee = U256::from(GAS_USED) * U256::from(GAS_PRICE as u128);
        let build = |coinbase_balance_after: U256| -> BatchInput {
            let sender_after = encode_account_props(1, sender_balance_before - fee);
            let coinbase_after = encode_account_props(0, coinbase_balance_after);
            let tree_update = BatchTreeUpdate {
                operations: vec![WriteOp::Update { index: 2 }, WriteOp::Update { index: 3 }],
                entries: vec![
                    (k_sender, AccountProperties::hash(&sender_after)),
                    (k_coinbase, AccountProperties::hash(&coinbase_after)),
                ],
                sorted_leaves: leaves.clone(),
                intermediate_hashes: vec![],
                leaf_count_before: 4,
            };
            let interop_proofs = Some(interop_proofs_nonsettlement(&tree_update));
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 1,
                spec_id: 2, // AtlasV3
                protocol_version_minor: 31,
                batch_meta: BatchMeta {
                    tree_root_before: root,
                    leaf_count_before: 4,
                    block_number_before: 0,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: empty_ring_blake(),
                    previous_block_hashes: vec![],
                    upgrade_tx_hash: B256::ZERO,
                    da_commitment_scheme: 2,
                    pubdata: vec![],
                    multichain_root: B256::ZERO,
                    sl_chain_id: 1,
                    blob_versioned_hashes: vec![],
                    tree_update: Some(tree_update),
                    account_preimages_after: vec![
                        (sender, sender_after.clone()),
                        (coinbase, coinbase_after.clone()),
                    ],
                    fri_proof_verification_enabled: false,
                    max_tx_gas_limit: 1 << 24,
                    interop_proofs,
                },
                blocks: vec![BlockInput {
                    number: 1,
                    timestamp: 1700000000,
                    base_fee: BASE_FEE,
                    gas_limit: 1_000_000,
                    coinbase,
                    prev_randao: B256::from([1u8; 32]),
                    block_header_hash: B256::ZERO,
                    storage_proofs: vec![(k_sender, proof_for(2)), (k_coinbase, proof_for(3))],
                    account_preimages: vec![
                        (sender, sender_props.clone()),
                        (coinbase, coinbase_props.clone()),
                    ],
                    transactions: vec![TxInput {
                        chain_id: Some(1),
                        gas_used_override: Some(GAS_USED),
                        force_fail: false,
                        auth: TxAuth::L2 { signed_bytes: signed_bytes.clone() },
                    }],
                    block_hashes: vec![],
                    l2_to_l1_logs: vec![],
                    expected_tree_root: B256::ZERO,
                }],
                bytecodes: vec![],
            }
        };

        // Full-price credit must verify end to end.
        let full_price = build(coinbase_balance_before + fee);
        let (output, _commitment) = executor::execute_and_commit(&full_price);
        let tx_out = &output.block_results[0].tx_results[0];
        assert!(tx_out.success, "self-transfer must succeed");
        assert_eq!(tx_out.gas_used, GAS_USED);

        // Mainnet burn semantics (tip-only credit) must be REJECTED: a witness
        // claiming coinbase += gas_used * (effective - base_fee) fails the
        // after-preimage balance check against REVM's full-price credit.
        let tip_only = build(
            coinbase_balance_before
                + U256::from(GAS_USED) * U256::from((GAS_PRICE - BASE_FEE) as u128),
        );
        let result = std::panic::catch_unwind(|| executor::execute_and_commit(&tip_only));
        assert!(
            result.is_err(),
            "tip-only (burn-semantics) coinbase credit must fail verification"
        );
    }

    /// Full 124-byte props blob for an account WITH code (code version 1).
    fn encode_account_props_code(nonce: u64, balance: U256, code: &[u8]) -> Vec<u8> {
        let mut data = encode_account_props(nonce, balance);
        if !code.is_empty() {
            let f = crate::account_props::evm_code_fields(code);
            data[0..8].copy_from_slice(&f.versioning.to_be_bytes());
            data[48..80].copy_from_slice(f.bytecode_hash.as_slice());
            data[80..84].copy_from_slice(&f.unpadded_code_len.to_be_bytes());
            data[84..88].copy_from_slice(&f.artifacts_len.to_be_bytes());
            data[88..120].copy_from_slice(f.observable_bytecode_hash.as_slice());
            data[120..124].copy_from_slice(&f.observable_bytecode_len.to_be_bytes());
        }
        data
    }

    /// Non-existence proof for `fk` from a `build_dense_tree` result.
    fn non_existence_proof(
        leaves: &[(u64, TreeLeaf)],
        siblings: &[Vec<B256>],
        fk: &B256,
    ) -> StorageProof {
        let (li, lleaf) = leaves
            .iter()
            .filter(|(_, l)| l.key < *fk)
            .max_by_key(|(_, l)| l.key)
            .expect("MIN guard");
        let (ri, rleaf) = leaves.iter().find(|(i, _)| *i == lleaf.next_index).unwrap();
        let entry = |i: u64, l: &TreeLeaf| SlotProofEntry {
            index: i,
            value: l.value,
            next_index: l.next_index,
            siblings: siblings[i as usize].clone(),
        };
        StorageProof::NonExisting {
            left_neighbor: NeighborProofEntry { entry: entry(*li, lleaf), leaf_key: lleaf.key },
            right_neighbor: NeighborProofEntry { entry: entry(*ri, rleaf), leaf_key: rleaf.key },
        }
    }

    /// Sign a legacy tx (chain 1, gas_price 10) with a deterministic key.
    fn sign_legacy(
        sk_bytes: [u8; 32],
        nonce: u64,
        to: Address,
        data: Vec<u8>,
        gas_limit: u64,
    ) -> (Address, Vec<u8>) {
        use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
        use alloy_eips::eip2718::Encodable2718;
        use k256::ecdsa::SigningKey;
        let sk = SigningKey::from_bytes((&sk_bytes).into()).unwrap();
        let pubkey = sk.verifying_key().to_encoded_point(false);
        let sender =
            Address::from_slice(&alloy_primitives::keccak256(&pubkey.as_bytes()[1..])[12..]);
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce,
            gas_price: 10,
            gas_limit,
            to: alloy_primitives::TxKind::Call(to),
            value: U256::ZERO,
            input: data.into(),
        };
        let sighash = tx.signature_hash();
        let (sig, recid) = sk.sign_prehash_recoverable(sighash.as_slice()).unwrap();
        let sig_bytes = sig.to_bytes();
        let signature = alloy_primitives::Signature::new(
            U256::from_be_slice(&sig_bytes[..32]),
            U256::from_be_slice(&sig_bytes[32..]),
            recid.is_y_odd(),
        );
        let envelope = TxEnvelope::Legacy(tx.into_signed(signature));
        let mut signed = Vec::new();
        envelope.encode_2718(&mut signed);
        (sender, signed)
    }

    /// `keccak256(rlp([deployer, nonce]))[12..]` for a single-byte nonce.
    fn create_address(deployer: Address, nonce: u8) -> Address {
        assert!(nonce > 0 && nonce < 0x80);
        let mut rlp = vec![0xd6, 0x94];
        rlp.extend_from_slice(deployer.as_slice());
        rlp.push(nonce);
        Address::from_slice(&alloy_primitives::keccak256(&rlp)[12..])
    }

    /// Assemble a single-block batch around the variable witness parts.
    fn selfdestruct_test_batch(
        root: B256,
        sorted_leaves: Vec<(u64, TreeLeaf)>,
        operations: Vec<WriteOp>,
        entries: Vec<(B256, B256)>,
        account_preimages_after: Vec<(Address, Vec<u8>)>,
        block: BlockInput,
        bytecodes: Vec<(B256, Vec<u8>)>,
    ) -> BatchInput {
        let leaf_count = sorted_leaves.len() as u64;
        let tree_update = BatchTreeUpdate {
            operations,
            entries,
            sorted_leaves,
            intermediate_hashes: vec![],
            leaf_count_before: leaf_count,
        };
        let interop_proofs = Some(interop_proofs_nonsettlement(&tree_update));
        BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 1,
            spec_id: 2, // AtlasV3
            protocol_version_minor: 31,
            batch_meta: BatchMeta {
                tree_root_before: root,
                leaf_count_before: leaf_count,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: empty_ring_blake(),
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 1,
                blob_versioned_hashes: vec![],
                tree_update: Some(tree_update),
                account_preimages_after,
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
                interop_proofs,
            },
            blocks: vec![block],
            bytecodes,
        }
    }

    /// Runtime payload: `SSTORE(1, 1); SELFDESTRUCT(CALLER)`.
    const SD_RUNTIME: [u8; 7] = [0x60, 0x01, 0x60, 0x01, 0x55, 0x33, 0xff];

    /// EIP-6780 arm 1: a contract created and selfdestructed within the same
    /// tx is destroyed — its SSTORE must NOT enter the guest's write set
    /// (native's tree diff has nothing for it). The witness claims only the
    /// surviving writes (sender/factory/coinbase props); before the
    /// `is_selfdestructed` filter this batch failed verification with a
    /// phantom (created, slot 1) write. Mirrors the corpus'
    /// prague/eip7702 factory fixtures.
    #[test]
    fn selfdestruct_created_same_tx_excluded_from_write_set() {
        // Factory: CALLDATACOPY(0,0,cds); CREATE(0,0,cds); CALL(gas, created,
        // 0,0,0,0,0); STOP.
        let factory_code: Vec<u8> = vec![
            0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // calldatacopy
            0x36, 0x60, 0x00, 0x60, 0x00, 0xf0, // create
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // ret/arg/value zeros
            0x85, 0x5a, 0xf1, 0x00, // dup6(addr) gas call stop
        ];
        // Initcode returning SD_RUNTIME: PUSH7 runtime; MSTORE@0; RETURN(25,7).
        let mut initcode: Vec<u8> = vec![0x66];
        initcode.extend_from_slice(&SD_RUNTIME);
        initcode.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x07, 0x60, 0x19, 0xf3]);

        let factory: Address = "0x00000000000000000000000000000000000fac70".parse().unwrap();
        let coinbase: Address = "0x00000000000000000000000000000000c01badde".parse().unwrap();
        let (sender, signed) = sign_legacy([0x51u8; 32], 0, factory, initcode, 1_000_000);
        let created = create_address(factory, 1);

        const GAS_USED: u64 = 100_000;
        let fee = U256::from(GAS_USED) * U256::from(10u64);
        let sender_before = U256::from(1_000_000_000_000_000_000u128);

        let sender_props = encode_account_props(0, sender_before);
        let factory_props = encode_account_props_code(1, U256::ZERO, &factory_code);
        let coinbase_props = encode_account_props(0, U256::from(5u64));
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_factory = derive_account_properties_key(&factory.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let k_created = derive_account_properties_key(&created.into_array());

        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_factory, AccountProperties::hash(&factory_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
        ]);
        let existing = |idx: u64| {
            let (_, leaf) = &leaves[idx as usize];
            StorageProof::Existing(SlotProofEntry {
                index: idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx as usize].clone(),
            })
        };

        // Surviving after-state: sender pays, factory nonce 1->2 (CREATE),
        // coinbase collects. The destroyed contract contributes NOTHING.
        let sender_after = encode_account_props(1, sender_before - fee);
        let factory_after = encode_account_props_code(2, U256::ZERO, &factory_code);
        let coinbase_after = encode_account_props(0, U256::from(5u64) + fee);

        let bi = selfdestruct_test_batch(
            root,
            leaves.clone(),
            vec![
                WriteOp::Update { index: 2 },
                WriteOp::Update { index: 3 },
                WriteOp::Update { index: 4 },
            ],
            vec![
                (k_sender, AccountProperties::hash(&sender_after)),
                (k_factory, AccountProperties::hash(&factory_after)),
                (k_coinbase, AccountProperties::hash(&coinbase_after)),
            ],
            vec![
                (sender, sender_after),
                (factory, factory_after),
                (coinbase, coinbase_after),
            ],
            BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 7,
                gas_limit: 10_000_000,
                coinbase,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![
                    (k_sender, existing(2)),
                    (k_factory, existing(3)),
                    (k_coinbase, existing(4)),
                    (k_created, non_existence_proof(&leaves, &siblings, &k_created)),
                ],
                account_preimages: vec![
                    (sender, sender_props),
                    (factory, factory_props.clone()),
                    (coinbase, coinbase_props),
                ],
                transactions: vec![TxInput {
                    chain_id: Some(1),
                    gas_used_override: Some(GAS_USED),
                    force_fail: false,
                    auth: TxAuth::L2 { signed_bytes: signed },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            },
            vec![(alloy_primitives::keccak256(&factory_code), factory_code.clone())],
        );

        let (output, _c) = executor::execute_and_commit(&bi);
        assert!(output.block_results[0].tx_results[0].success, "factory tx must succeed");
    }

    /// EIP-6780 arm 2: SELFDESTRUCT of a PRE-EXISTING account is only a
    /// balance transfer post-Cancun — the account and its storage writes
    /// survive. The witness claims the SSTORE (a tree insert); if the
    /// selfdestruct filter over-skipped, the write would go missing and
    /// verification would fail.
    #[test]
    fn selfdestruct_of_preexisting_account_keeps_storage_writes() {
        let d_addr: Address = "0x00000000000000000000000000000000000dcafe".parse().unwrap();
        let coinbase: Address = "0x00000000000000000000000000000000c01badde".parse().unwrap();
        let d_code = SD_RUNTIME.to_vec();
        let (sender, signed) = sign_legacy([0x52u8; 32], 0, d_addr, vec![], 1_000_000);

        const GAS_USED: u64 = 100_000;
        let fee = U256::from(GAS_USED) * U256::from(10u64);
        let sender_before = U256::from(1_000_000_000_000_000_000u128);

        let sender_props = encode_account_props(0, sender_before);
        let d_props = encode_account_props_code(1, U256::ZERO, &d_code);
        let coinbase_props = encode_account_props(0, U256::from(5u64));
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_d = derive_account_properties_key(&d_addr.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let k_slot1 = derive_flat_storage_key(
            &d_addr.into_array(),
            &B256::from(U256::from(1u64).to_be_bytes::<32>()),
        );

        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_d, AccountProperties::hash(&d_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
        ]);
        let existing = |idx: u64| {
            let (_, leaf) = &leaves[idx as usize];
            StorageProof::Existing(SlotProofEntry {
                index: idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx as usize].clone(),
            })
        };
        // Insert predecessor for the new (D, slot 1) leaf.
        let prev_index = leaves
            .iter()
            .filter(|(_, l)| l.key < k_slot1)
            .max_by_key(|(_, l)| l.key)
            .unwrap()
            .0;

        let sender_after = encode_account_props(1, sender_before - fee);
        let coinbase_after = encode_account_props(0, U256::from(5u64) + fee);

        let bi = selfdestruct_test_batch(
            root,
            leaves.clone(),
            vec![
                WriteOp::Update { index: 2 },
                WriteOp::Update { index: 4 },
                WriteOp::Insert { prev_index },
            ],
            vec![
                (k_sender, AccountProperties::hash(&sender_after)),
                (k_coinbase, AccountProperties::hash(&coinbase_after)),
                (k_slot1, B256::from(U256::from(1u64).to_be_bytes::<32>())),
            ],
            vec![(sender, sender_after), (coinbase, coinbase_after)],
            BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 7,
                gas_limit: 10_000_000,
                coinbase,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![
                    (k_sender, existing(2)),
                    (k_d, existing(3)),
                    (k_coinbase, existing(4)),
                    (k_slot1, non_existence_proof(&leaves, &siblings, &k_slot1)),
                ],
                account_preimages: vec![
                    (sender, sender_props),
                    (d_addr, d_props),
                    (coinbase, coinbase_props),
                ],
                transactions: vec![TxInput {
                    chain_id: Some(1),
                    gas_used_override: Some(GAS_USED),
                    force_fail: false,
                    auth: TxAuth::L2 { signed_bytes: signed },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            },
            vec![(alloy_primitives::keccak256(&d_code), d_code.clone())],
        );

        let (output, _c) = executor::execute_and_commit(&bi);
        assert!(output.block_results[0].tx_results[0].success, "call to D must succeed");
    }

    /// Execute a dumped batch input (a divergence repro bundle or a
    /// `ZISK_DUMP_DIR` capture) through the proven executor.
    /// Invoke with:
    ///   ZISK_BATCH_PATH=... cargo test --release execute_batch_dump -- --ignored --nocapture
    #[test]
    #[ignore]
    fn execute_batch_dump() {
        let path = std::env::var("ZISK_BATCH_PATH").expect("set ZISK_BATCH_PATH to a dump file");
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        // ZiSK stdin framing: [len: u64 LE][bincode][zero pad].
        let len = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        match crate::executor::execute_and_commit_from_bincode(&data[8..8 + len]) {
            Ok((output, commitment)) => println!(
                "OK: {} blocks, commitment {commitment}",
                output.block_results.len()
            ),
            Err(e) => panic!("executor failed: {e:#}"),
        }
    }

    /// Regression for the historical block-hash ring soundness gap.
    ///
    /// The pre-batch block-hash ring (`first_block.block_hashes`) feeds the
    /// `BLOCKHASH` opcode, the first block's parent hash, and — via
    /// `block_hashes_blake_after` — `state_after`. Previously the only check on
    /// it compared two witness fields against each other; nothing tied it to the
    /// L1-pinned `block_hashes_blake_before`. A malicious sequencer could supply
    /// a forged-but-internally-consistent ring and the guest would fold forged
    /// `BLOCKHASH` values / a forged ring commitment into its proof.
    ///
    /// This batch starts at block 6 (`block_number_before = 5`), so the first
    /// block's BLOCKHASH-visible window is blocks 0..=5. With a single block and
    /// number < 255 there is NO `previous_block_hashes` cross-check
    /// (`proven_db.rs`), so the reconstruction-vs-pinned assertion is the only
    /// thing standing between a forged history and the commitment.
    #[test]
    fn historical_block_hash_ring_authenticated_against_pinned() {
        const FIRST: u64 = 6;

        // Minimal tree with a single sender leaf (as in test_proven_path).
        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let sender_props_hash = AccountProperties::hash(&sender_props);
        let sender_flat_key = derive_account_properties_key(&sender.into_array());
        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        // force_fail L1 tx: exercises the full commit path without needing
        // proofs for accounts a real execution would touch.
        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20;
            abi[32 + 31] = 0x7f;
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice());
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice());
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes());
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice());
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        // Honest pre-state history: blocks 0..=5 (the ring's other 250 slots are
        // genesis padding = zero).
        let history: Vec<(u64, B256)> =
            (0..=5u64).map(|n| (n, B256::repeat_byte((n as u8) + 0x11))).collect();

        // Pinned commitment computed INDEPENDENTLY of the executor, exactly as
        // the server does: Blake2s over the full 256-entry ring, oldest at
        // index 0, the first block's parent (block 5) at index 255.
        let pinned_blake = {
            use blake2::{Blake2s256, Digest};
            let mut ring = [B256::ZERO; 256];
            for &(n, h) in &history {
                ring[(n + 256 - FIRST) as usize] = h;
            }
            let mut hasher = Blake2s256::new();
            for e in &ring {
                hasher.update(e.as_slice());
            }
            B256::from_slice(&hasher.finalize())
        };

        let build = |block_hashes: Vec<(u64, B256)>| -> BatchInput {
            let proof = StorageProof::Existing(SlotProofEntry {
                index: 2,
                value: sender_props_hash,
                next_index: 1,
                siblings: siblings.clone(),
            });
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 270,
                spec_id: 1,
                protocol_version_minor: 30,
                batch_meta: BatchMeta {
                    tree_root_before: tree_root,
                    leaf_count_before: leaf_count,
                    block_number_before: FIRST - 1,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: pinned_blake,
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
                blocks: vec![BlockInput {
                    number: FIRST,
                    timestamp: 1700000000,
                    base_fee: 250_000_000,
                    gas_limit: 80_000_000,
                    coinbase: sender,
                    prev_randao: B256::from([1u8; 32]),
                    block_header_hash: B256::ZERO,
                    storage_proofs: vec![(sender_flat_key, proof)],
                    account_preimages: vec![(sender, sender_props.clone())],
                    transactions: vec![TxInput {
                        chain_id: Some(270),
                        gas_used_override: Some(0),
                        force_fail: true,
                        auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                    }],
                    block_hashes,
                    l2_to_l1_logs: vec![L2ToL1LogEntry {
                        l2_shard_id: 0,
                        is_service: true,
                        tx_number_in_block: 0,
                        sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                        key: l1_tx_hash,
                        value: B256::ZERO,
                    }],
                    expected_tree_root: B256::ZERO,
                }],
                bytecodes: vec![],
            }
        };

        // Honest: the witnessed history reconstructs to the pinned commitment.
        let (_output, commitment) = executor::execute_and_commit(&build(history.clone()));
        assert_ne!(commitment, B256::ZERO, "honest batch must commit");

        // Forged: BLOCKHASH(3) is tampered while the L1-chained pinned
        // commitment is unchanged. Internally consistent with every other
        // witness field, yet it no longer reconstructs the pinned ring.
        let mut forged = history.clone();
        forged[3].1 = B256::repeat_byte(0xff);
        assert_ne!(forged, history, "forged ring must actually differ");
        let res = std::panic::catch_unwind(|| {
            executor::execute_and_commit(&build(forged));
        });
        assert!(
            res.is_err(),
            "forged pre-state block-hash ring must be rejected by the \
             block_hashes_blake_before authentication check"
        );
    }

    /// Multi-block (2 blocks) batch over a FULL pre-state ring
    /// (`block_number_before = 300 >= 256`, so all 256 ring entries are
    /// non-zero). Covers the windowing paths the single-block/short-ring test
    /// did not: `block_number_before >= 255` (so `proven_db`'s
    /// `previous_block_hashes` cross-check is active), and a batch longer than
    /// one block.
    ///
    /// The pinned `block_hashes_blake_before` is computed EXACTLY as the server
    /// does (`zksync-os-server` `batcher/batch_builder.rs`): Blake2s256 over the
    /// FIRST block's full 256-entry context ring in array order [0..255], each
    /// entry 32 big-endian bytes; ring index `i` ↔ block `first - 256 + i`
    /// (oldest at 0, `block_number_before` at 255). The guest's reconstruction
    /// must reproduce this, and — because it reads only `blocks[0].block_hashes`
    /// — must be independent of batch length.
    #[test]
    fn multiblock_full_ring_block_hashes_authenticated() {
        use blake2::{Blake2s256, Digest};

        const BNB: u64 = 300;
        const FIRST: u64 = BNB + 1; // 301
        const LAST: u64 = FIRST + 1; // 302

        // Distinct non-zero, big-endian-encoded historical hash per block.
        let hh = |num: u64| -> B256 {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&num.to_be_bytes());
            b[31] = 0xA5;
            B256::from(b)
        };

        // First block's ring window: blocks (FIRST-256)..=(FIRST-1) = 45..=300.
        let first_block_hashes: Vec<(u64, B256)> =
            ((FIRST - 256)..FIRST).map(|n| (n, hh(n))).collect();
        assert_eq!(first_block_hashes.len(), 256, "full ring: 256 non-zero entries");

        // Pinned value the SERVER way: Blake2s over the full 256-entry ring,
        // array order, oldest (block 45) at index 0, block 300 at index 255.
        let server_pinned = {
            let mut ring = [B256::ZERO; 256];
            for &(n, h) in &first_block_hashes {
                ring[(n + 256 - FIRST) as usize] = h;
            }
            let mut hasher = Blake2s256::new();
            for e in &ring {
                hasher.update(e.as_slice());
            }
            B256::from_slice(&hasher.finalize())
        };

        // The guest reconstruction must reproduce the server value exactly.
        assert_eq!(
            executor::reconstruct_block_hashes_blake_before(FIRST, &first_block_hashes),
            server_pinned,
            "guest reconstruction must equal the server's Blake2s-over-256-ring"
        );

        // Batch-length independence: reconstruction reads only the first block's
        // hashes, so appending more blocks cannot change it.
        assert_eq!(
            executor::reconstruct_block_hashes_blake_before(FIRST, &first_block_hashes),
            executor::reconstruct_block_hashes_blake_before(
                FIRST,
                &first_block_hashes.iter().copied().collect::<Vec<_>>()
            ),
            "reconstruction must depend only on blocks[0].block_hashes"
        );

        // Second block (302) window [46,301]; omit block 301 (computed within
        // the batch) so `verify_intra_batch_hashes` has nothing to cross-check.
        let second_block_hashes: Vec<(u64, B256)> =
            ((LAST - 256)..(LAST - 1)).map(|n| (n, hh(n))).collect(); // 46..=300

        // previous_block_hashes: 255 entries, index j ↔ block (LAST-255+j)=47+j
        // → blocks 47..=301. Block 301 (idx 254, computed within the batch) is
        // never referenced by any block_hashes entry, so leave it zero (the
        // cross-check skips zero entries; it only feeds the in-guest-unchecked
        // block_hashes_blake_after).
        let previous_block_hashes: Vec<B256> = (0..255u64)
            .map(|j| {
                let num = (LAST - 255) + j;
                if num < LAST - 1 { hh(num) } else { B256::ZERO }
            })
            .collect();

        // ---- tree + force_fail L1 tx (coinbase = sender, so no extra proof) ----
        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let sender_props_hash = AccountProperties::hash(&sender_props);
        let sender_flat_key = derive_account_properties_key(&sender.into_array());
        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20;
            abi[32 + 31] = 0x7f;
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice());
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice());
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes());
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice());
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        let mk_block = |number: u64, block_hashes: Vec<(u64, B256)>| -> BlockInput {
            BlockInput {
                number,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(
                    sender_flat_key,
                    StorageProof::Existing(SlotProofEntry {
                        index: 2,
                        value: sender_props_hash,
                        next_index: 1,
                        siblings: siblings.clone(),
                    }),
                )],
                account_preimages: vec![(sender, sender_props.clone())],
                transactions: vec![TxInput {
                    chain_id: Some(270),
                    gas_used_override: Some(0),
                    force_fail: true,
                    auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                }],
                block_hashes,
                l2_to_l1_logs: vec![L2ToL1LogEntry {
                    l2_shard_id: 0,
                    is_service: true,
                    tx_number_in_block: 0,
                    sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                    key: l1_tx_hash,
                    value: B256::ZERO,
                }],
                expected_tree_root: B256::ZERO,
            }
        };

        let build = |first_bh: Vec<(u64, B256)>,
                     second_bh: Vec<(u64, B256)>,
                     prev_bh: Vec<B256>|
         -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 270,
                spec_id: 1,
                protocol_version_minor: 30,
                batch_meta: BatchMeta {
                    tree_root_before: tree_root,
                    leaf_count_before: leaf_count,
                    block_number_before: BNB,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: server_pinned,
                    previous_block_hashes: prev_bh,
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
                blocks: vec![mk_block(FIRST, first_bh), mk_block(LAST, second_bh)],
                bytecodes: vec![],
            }
        };

        // Honest: witnessed history reconstructs to the pinned commitment, and
        // every other witness field is internally consistent → accepted.
        let (output, commitment) = executor::execute_and_commit(&build(
            first_block_hashes.clone(),
            second_block_hashes.clone(),
            previous_block_hashes.clone(),
        ));
        assert_eq!(output.block_results.len(), 2, "two blocks executed");
        assert_ne!(commitment, B256::ZERO, "honest multi-block batch must commit");

        // Forged: tamper block 100's hash. To keep every OTHER witness field
        // internally consistent (so the ONLY failing check is the ring
        // authentication), the tamper is applied identically in both blocks'
        // block_hashes AND in previous_block_hashes — the two witness fields
        // still agree with each other and pass proven_db's cross-check — but the
        // pinned (L1-chained) commitment is left unchanged.
        let tamper = |bh: &[(u64, B256)]| -> Vec<(u64, B256)> {
            bh.iter()
                .map(|&(n, h)| if n == 100 { (n, B256::repeat_byte(0xff)) } else { (n, h) })
                .collect()
        };
        let forged_prev: Vec<B256> = previous_block_hashes
            .iter()
            .enumerate()
            .map(|(j, &h)| if (LAST - 255) + j as u64 == 100 { B256::repeat_byte(0xff) } else { h })
            .collect();
        let forged = build(
            tamper(&first_block_hashes),
            tamper(&second_block_hashes),
            forged_prev,
        );
        let res = std::panic::catch_unwind(|| {
            executor::execute_and_commit(&forged);
        });
        assert!(
            res.is_err(),
            "forged historical hash in a full-ring multi-block batch must be \
             rejected despite the witness fields agreeing with each other"
        );
    }

    // ======== after-ring anchoring (regression) ========
    //
    // Question under test: is `meta.previous_block_hashes` (the pre-fix input to
    // `block_hashes_blake_after` / `state_after`) soundly anchored, or could an
    // operator forge an entry that passes every in-guest check while differing
    // from the true block-hash ring?
    //
    // Pre-fix, `previous_block_hashes` was folded verbatim into `state_after`
    // and checked only by the cross-check in `proven_db::build_block_hashes`,
    // which fires for a slot only when SOME block lists that block in its
    // `block_hashes` AND `previous_block_hashes[idx] != 0`. Two seams left slots
    // as free parameters of `state_after`, and both tests below ORIGINALLY
    // accepted the forgery.
    //
    // The fix: `block_hashes_blake_after` is now reconstructed in
    // `run_execution_and_commit` from authenticated data only (the L1-pinned
    // before-ring plus the guest's `computed_block_hashes`); the witness ring is
    // never folded in. The tests therefore now assert the forgery is NEUTRALIZED
    // (forged and honest runs commit to the SAME value), and each keeps a
    // secondary control showing the pre-existing proven_db cross-check still
    // fires where it can.

    /// SEAM 1 (the windowing seam, multi-block): the slot for the batch's OWN
    /// first block. Its block number is > `first-1`, so it is outside the
    /// pre-state before-ring window `[first-256, first-1]`, and if the last block
    /// OMITS its parent from `block_hashes` (parent_hash then defaults to zero
    /// via `evm.rs`'s `unwrap_or(ZERO)`, `block_header_hash` unchecked), nothing
    /// references it: pre-fix it fed `block_hashes_blake_after` unconstrained.
    ///
    /// This test drives THREE runs that differ ONLY in that one slot. Post-fix
    /// the slot is taken from `computed_block_hashes` regardless of the witness,
    /// so all three now produce the SAME commitment (forgery neutralized).
    #[test]
    fn after_ring_own_first_block_slot_unanchored() {
        use blake2::{Blake2s256, Digest};

        const BNB: u64 = 300;
        const FIRST: u64 = BNB + 1; // 301
        const LAST: u64 = FIRST + 1; // 302

        let hh = |num: u64| -> B256 {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&num.to_be_bytes());
            b[31] = 0xA5;
            B256::from(b)
        };

        // First block's before-ring window: blocks 45..=300 (256 non-zero).
        let first_block_hashes: Vec<(u64, B256)> =
            ((FIRST - 256)..FIRST).map(|n| (n, hh(n))).collect();

        // Pinned before-value computed the server way (Blake2s over 256-ring).
        let server_pinned = {
            let mut ring = [B256::ZERO; 256];
            for &(n, h) in &first_block_hashes {
                ring[(n + 256 - FIRST) as usize] = h;
            }
            let mut hasher = Blake2s256::new();
            for e in &ring {
                hasher.update(e.as_slice());
            }
            B256::from_slice(&hasher.finalize())
        };

        // Last block (302) OMITS its parent (301) from block_hashes -> the seam
        // is open: no block references block 301, so neither the intra-batch
        // check nor proven_db's cross-check ever touches previous_block_hashes
        // index 254 (block 301).
        let second_block_hashes: Vec<(u64, B256)> =
            ((LAST - 256)..(LAST - 1)).map(|n| (n, hh(n))).collect(); // 46..=300

        // index j <-> block (LAST-255+j) = 47+j -> 47..=301. Blocks 47..=300
        // (j in 0..=253) carry the true historical hash; slot j=254 (block 301,
        // the batch's OWN first block) is the variable under test.
        let prev_with_slot254 = |slot254: B256| -> Vec<B256> {
            (0..255u64)
                .map(|j| {
                    let num = (LAST - 255) + j;
                    if num == LAST - 1 { slot254 } else { hh(num) }
                })
                .collect()
        };

        // ---- minimal tree + force_fail L1 tx (coinbase = sender) ----
        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let sender_props_hash = AccountProperties::hash(&sender_props);
        let sender_flat_key = derive_account_properties_key(&sender.into_array());
        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20;
            abi[32 + 31] = 0x7f;
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice());
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice());
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes());
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice());
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        let mk_block = |number: u64, block_hashes: Vec<(u64, B256)>| -> BlockInput {
            BlockInput {
                number,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(
                    sender_flat_key,
                    StorageProof::Existing(SlotProofEntry {
                        index: 2,
                        value: sender_props_hash,
                        next_index: 1,
                        siblings: siblings.clone(),
                    }),
                )],
                account_preimages: vec![(sender, sender_props.clone())],
                transactions: vec![TxInput {
                    chain_id: Some(270),
                    gas_used_override: Some(0),
                    force_fail: true,
                    auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                }],
                block_hashes,
                l2_to_l1_logs: vec![L2ToL1LogEntry {
                    l2_shard_id: 0,
                    is_service: true,
                    tx_number_in_block: 0,
                    sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                    key: l1_tx_hash,
                    value: B256::ZERO,
                }],
                expected_tree_root: B256::ZERO,
            }
        };

        let build = |second_bh: Vec<(u64, B256)>, prev_bh: Vec<B256>| -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 270,
                spec_id: 1,
                protocol_version_minor: 30,
                batch_meta: BatchMeta {
                    tree_root_before: tree_root,
                    leaf_count_before: leaf_count,
                    block_number_before: BNB,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: server_pinned,
                    previous_block_hashes: prev_bh,
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
                blocks: vec![mk_block(FIRST, first_block_hashes.clone()), mk_block(LAST, second_bh)],
                bytecodes: vec![],
            }
        };

        // Run once (slot254 = 0) to learn the TRUE in-guest computed hash of the
        // batch's own first block 301 — the value the after-ring SHOULD carry.
        let (out0, c_zero) =
            executor::execute_and_commit(&build(second_block_hashes.clone(), prev_with_slot254(B256::ZERO)));
        let true_301 = out0.block_results[0].computed_block_header_hash;
        assert_eq!(out0.block_results[0].block_number, FIRST);
        assert_ne!(true_301, B256::ZERO, "block 301 must have a non-zero computed hash");

        // Slot254 = the TRUE hash (what an honest full witness would carry).
        let (_out_t, c_true) =
            executor::execute_and_commit(&build(second_block_hashes.clone(), prev_with_slot254(true_301)));

        // Slot254 = an ARBITRARY forged value that is NOT the true hash.
        let forged_val = B256::repeat_byte(0xEE);
        assert_ne!(forged_val, true_301, "forged value must differ from the true hash");
        assert_ne!(forged_val, B256::ZERO);
        let (_out_f, c_forged) =
            executor::execute_and_commit(&build(second_block_hashes.clone(), prev_with_slot254(forged_val)));

        // After the fix, `block_hashes_blake_after` is reconstructed
        // from authenticated data only (the L1-pinned before-ring plus the
        // guest's own `computed_block_hashes`); `meta.previous_block_hashes` is
        // never folded into `state_after`. Slot 254 is block 301 (the batch's
        // OWN first block, an intra-batch block), whose value is taken from
        // `computed_block_hashes[301]` regardless of the witness. The forgery is
        // therefore NEUTRALIZED: all three runs commit to the SAME value, so the
        // operator can no longer fold an arbitrary hash into state_after.
        assert_eq!(c_zero, c_true, "zeroed slot must NOT change state_after");
        assert_eq!(c_true, c_forged, "forged slot must NOT change state_after");
        assert_eq!(c_zero, c_forged, "all forgeries collapse to the honest commitment");

        // ---- Secondary guard (pre-existing proven_db cross-check) ----------
        // When the last block DOES list its parent (301, true_301), the
        // proven_db cross-check additionally rejects a non-zero forged slot with
        // a hard panic. This layered defense is orthogonal to (and survives) the
        // reconstruction fix above; the honest anchored witness still passes.
        let mut anchored_second: Vec<(u64, B256)> = second_block_hashes.clone();
        anchored_second.push((FIRST, true_301)); // block 302 lists parent 301

        // With the slot set honestly, the anchored witness passes.
        let (_o, _c_ok) =
            executor::execute_and_commit(&build(anchored_second.clone(), prev_with_slot254(true_301)));

        // With the slot forged, the cross-check rejects it.
        let rejected = std::panic::catch_unwind(|| {
            executor::execute_and_commit(&build(anchored_second.clone(), prev_with_slot254(forged_val)));
        });
        assert!(
            rejected.is_err(),
            "when the last block anchors block 301, forging its after-ring slot MUST be rejected"
        );
    }

    /// SEAM 2 (the zero guard, single-block): the `if !verified_hash.is_zero()`
    /// guard in `proven_db::build_block_hashes` let an operator ZERO OUT a
    /// `previous_block_hashes` slot whose TRUE value is non-zero, even for a
    /// pre-state block that IS listed in `block_hashes` and IS inside the pinned
    /// before-ring window: the cross-check silently skipped the zeroed slot and
    /// (pre-fix) it flowed into `block_hashes_blake_after`. Post-fix that slot is
    /// pre-batch, so its value is taken from the L1-authenticated before-ring and
    /// the zeroing no longer reaches `state_after`. Single-block, full ring
    /// (N=300).
    #[test]
    fn after_ring_zero_guard_seam() {
        use blake2::{Blake2s256, Digest};

        const N: u64 = 300; // last_num >= 255 -> the cross-check branch is active

        let hh = |num: u64| -> B256 {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&num.to_be_bytes());
            b[31] = 0x5A;
            B256::from(b)
        };

        // Before-ring window for block N: blocks (N-256)..=(N-1) = 44..=299.
        let block_hashes: Vec<(u64, B256)> = ((N - 256)..N).map(|n| (n, hh(n))).collect();
        let server_pinned = {
            let mut ring = [B256::ZERO; 256];
            for &(n, h) in &block_hashes {
                ring[(n + 256 - N) as usize] = h;
            }
            let mut hasher = Blake2s256::new();
            for e in &ring {
                hasher.update(e.as_slice());
            }
            B256::from_slice(&hasher.finalize())
        };

        // after-ring previous entries: index j <-> block (N-255+j) = 45+j ->
        // 45..=299. Honest: every slot carries its true historical hash. Block
        // 100 sits at index 100-45 = 55, is listed in block_hashes, and is inside
        // the before-ring window — the "most anchored" kind of slot.
        let honest_prev: Vec<B256> = (0..255u64).map(|j| hh((N - 255) + j)).collect();
        let mut forged_prev = honest_prev.clone();
        forged_prev[(100 - (N - 255)) as usize] = B256::ZERO; // zero out block 100's slot

        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let sender_props_hash = AccountProperties::hash(&sender_props);
        let sender_flat_key = derive_account_properties_key(&sender.into_array());
        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20;
            abi[32 + 31] = 0x7f;
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice());
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice());
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes());
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice());
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        let build = |prev_bh: Vec<B256>| -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 270,
                spec_id: 1,
                protocol_version_minor: 30,
                batch_meta: BatchMeta {
                    tree_root_before: tree_root,
                    leaf_count_before: leaf_count,
                    block_number_before: N - 1,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: server_pinned,
                    previous_block_hashes: prev_bh,
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
                blocks: vec![BlockInput {
                    number: N,
                    timestamp: 1700000000,
                    base_fee: 250_000_000,
                    gas_limit: 80_000_000,
                    coinbase: sender,
                    prev_randao: B256::from([1u8; 32]),
                    block_header_hash: B256::ZERO,
                    storage_proofs: vec![(
                        sender_flat_key,
                        StorageProof::Existing(SlotProofEntry {
                            index: 2,
                            value: sender_props_hash,
                            next_index: 1,
                            siblings: siblings.clone(),
                        }),
                    )],
                    account_preimages: vec![(sender, sender_props.clone())],
                    transactions: vec![TxInput {
                        chain_id: Some(270),
                        gas_used_override: Some(0),
                        force_fail: true,
                        auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                    }],
                    block_hashes: block_hashes.clone(),
                    l2_to_l1_logs: vec![L2ToL1LogEntry {
                        l2_shard_id: 0,
                        is_service: true,
                        tx_number_in_block: 0,
                        sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                        key: l1_tx_hash,
                        value: B256::ZERO,
                    }],
                    expected_tree_root: B256::ZERO,
                }],
                bytecodes: vec![],
            }
        };

        // After the fix, the after-ring is reconstructed from
        // authenticated data. Slot 55 (block 100) is pre-batch, so its value is
        // taken from the L1-authenticated before-ring, NOT from the witness
        // `previous_block_hashes`. Zeroing the witness slot no longer reaches
        // `state_after` — the zero guard in proven_db is irrelevant to the
        // commitment now — so the honest and "zeroed" runs commit to the SAME
        // value. The forgery is neutralized.
        let (_oh, c_honest) = executor::execute_and_commit(&build(honest_prev.clone()));
        let (_of, c_forged) = executor::execute_and_commit(&build(forged_prev.clone()));

        assert_eq!(
            c_honest, c_forged,
            "zeroing a pre-state previous_block_hashes slot must NOT change state_after"
        );

        // Negative control: had proven_db cross-checked without the zero guard,
        // a *non-zero* forgery of the SAME (listed, in-window) slot would be
        // rejected — confirming the ONLY thing that lets slot 55 be forged is
        // the zero guard, not a broken harness.
        let mut nonzero_forge = honest_prev.clone();
        nonzero_forge[(100 - (N - 255)) as usize] = B256::repeat_byte(0xEE);
        let rejected = std::panic::catch_unwind(|| {
            executor::execute_and_commit(&build(nonzero_forge));
        });
        assert!(
            rejected.is_err(),
            "a non-zero forgery of a listed in-window slot IS caught by the cross-check"
        );
    }

    /// GENESIS BOUNDARY: for the first batch the after-window still reaches
    /// block 0 (genesis). With `F = 1` and `L = 1`, after-window position 254 is
    /// block 0. Genesis is a real block with an authenticated hash, held in the
    /// L1-anchored before-ring at `before_ring[255]`. The reconstruction must
    /// read that hash into the after-window. It must not zero the slot.
    ///
    /// This is a direct, non-vacuous check on the pre-genesis guard. Reverting
    /// the guard to `n < 1` zeroes block 0. That makes the reconstructed
    /// `block_hashes_blake_after` (and therefore `state_after`) equal the buggy
    /// all-zero-window value and fails both assertions below.
    #[test]
    fn after_window_keeps_genesis_hash_first_batch() {
        const FIRST: u64 = 1; // genesis (block 0) is the parent of the first block
        const LAST: u64 = 1; // single-block first batch

        // Distinct non-zero hashes so a zeroed slot is detectable.
        let genesis = B256::repeat_byte(0x11);
        let block1 = B256::repeat_byte(0x22);

        // Before-ring owned by block FIRST=1: its parent (genesis, block 0) sits
        // at index 255. Every other slot is pre-genesis padding and stays zero.
        // This is the ring the server authenticates via block_hashes_blake_before.
        let mut before_ring = [B256::ZERO; 256];
        before_ring[255] = genesis;

        // Single-block batch: no intra-batch predecessor blocks exist.
        let computed_block_hashes = std::collections::HashMap::new();

        let got = executor::reconstruct_block_hashes_blake_after(
            FIRST,
            LAST,
            &before_ring,
            &computed_block_hashes,
            &block1,
        );

        // Honest/native reconstruction: the 255 "previous" slots carry genesis at
        // position 254 (block 0); the current slot is block 1. This equals what
        // native computes as block_hashes_blake(&previous_block_hashes, &last).
        let mut previous = [B256::ZERO; 255];
        previous[254] = genesis;
        let honest = crate::commitment::block_hashes_blake(&previous, &block1);
        assert_eq!(
            got, honest,
            "after-window position 254 must carry the authenticated genesis hash"
        );

        // Buggy reconstruction: genesis zeroed. The old `n < 1` guard produced this.
        let buggy = crate::commitment::block_hashes_blake(&[B256::ZERO; 255], &block1);
        assert_ne!(
            got, buggy,
            "the after-window must NOT zero genesis (regression guard)"
        );

        // The divergence propagates into the committed state_after. Fold each
        // block_hashes_blake_after through the same state commitment the guest
        // uses. The honest genesis-bearing value and the buggy zeroed value give
        // different commitments, so keeping genesis is load-bearing for soundness.
        let tree_root = B256::repeat_byte(0x33);
        let leaf_count = 3u64;
        let timestamp = 1_700_000_000u64;
        let state_after_got =
            crate::commitment::state_commitment_hash(&tree_root, leaf_count, LAST, &got, timestamp);
        let state_after_honest = crate::commitment::state_commitment_hash(
            &tree_root, leaf_count, LAST, &honest, timestamp,
        );
        let state_after_buggy = crate::commitment::state_commitment_hash(
            &tree_root, leaf_count, LAST, &buggy, timestamp,
        );
        assert_eq!(
            state_after_got, state_after_honest,
            "committed state_after must match the honest/native reconstruction"
        );
        assert_ne!(
            state_after_got, state_after_buggy,
            "committed state_after must differ from the genesis-zeroed value"
        );

        // Second-prover independence: the kept hash is exactly the authenticated
        // before-ring slot, never a witness field.
        assert_eq!(before_ring[255], genesis);
    }

    /// The BLOCKHASH execution map must come from authenticated data only. A
    /// contract runs `SSTORE(0, BLOCKHASH(3))`; block 3 is a pre-batch block that
    /// `blocks[0]` pins correctly (it is inside the L1-authenticated before-ring).
    /// `blocks[1]` supplies a FORGED hash for block 3. The stored value must
    /// equal the authenticated before-ring hash regardless of `blocks[1]`, so the
    /// honest and forged runs commit to the SAME value (the forgery is
    /// neutralized). Before the fix, the map merged every block's witnessed hashes
    /// last-writer-wins, so `blocks[1]` could overwrite block 3 and drive the
    /// stored value.
    #[test]
    fn blockhash_map_uses_authenticated_before_ring_not_later_block() {
        use blake2::{Blake2s256, Digest};

        const BNB: u64 = 5;
        const FIRST: u64 = BNB + 1; // 6
        const LAST: u64 = FIRST + 1; // 7
        const P: u64 = 3; // pre-batch block the contract reads with BLOCKHASH

        // Distinct non-zero historical hash per block.
        let hh = |num: u64| -> B256 {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&num.to_be_bytes());
            b[31] = 0xA5;
            B256::from(b)
        };
        let true_p = hh(P);

        // First block's witnessed history: blocks 0..=5 (the rest of the ring is
        // genesis padding). This reconstructs the L1-pinned before-ring.
        let history: Vec<(u64, B256)> = (0..=BNB).map(|n| (n, hh(n))).collect();
        let server_pinned = {
            let mut ring = [B256::ZERO; 256];
            for &(n, h) in &history {
                ring[(n + 256 - FIRST) as usize] = h;
            }
            let mut hasher = Blake2s256::new();
            for e in &ring {
                hasher.update(e.as_slice());
            }
            B256::from_slice(&hasher.finalize())
        };

        // Contract C: PUSH1 3; BLOCKHASH; PUSH1 0; SSTORE; STOP.
        let c_code: Vec<u8> = vec![0x60, P as u8, 0x40, 0x60, 0x00, 0x55, 0x00];
        let c_addr: Address = "0x00000000000000000000000000000000c0de0001".parse().unwrap();
        let coinbase: Address = "0x00000000000000000000000000000000c01badde".parse().unwrap();
        // Gas limit stays under the chain `max_tx_gas_limit` (1 << 24); the
        // tx only runs BLOCKHASH+SSTORE, so a modest limit is enough.
        let (sender, signed) = sign_legacy([0x42u8; 32], 0, c_addr, vec![], 10_000_000);

        const GAS_USED: u64 = 100_000;
        let fee = U256::from(GAS_USED) * U256::from(10u64);
        let sender_before = U256::from(1_000_000_000_000_000_000u128);
        let coinbase_before = U256::from(5u64);

        let sender_props = encode_account_props(0, sender_before);
        let c_props = encode_account_props_code(1, U256::ZERO, &c_code);
        let coinbase_props = encode_account_props(0, coinbase_before);
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_c = derive_account_properties_key(&c_addr.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let k_c_slot0 = derive_flat_storage_key(&c_addr.into_array(), &B256::ZERO);

        // idx2=sender, idx3=C, idx4=coinbase, idx5=C-slot0 (pre-state value 0).
        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_c, AccountProperties::hash(&c_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
            (k_c_slot0, B256::ZERO),
        ]);
        let existing = |idx: u64| -> StorageProof {
            let (_, leaf) = &leaves[idx as usize];
            StorageProof::Existing(SlotProofEntry {
                index: idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx as usize].clone(),
            })
        };

        let sender_after = encode_account_props(1, sender_before - fee);
        let coinbase_after = encode_account_props(0, coinbase_before + fee);

        // C-slot0 must hold the AUTHENTICATED BLOCKHASH(3) = before-ring hash.
        let tree_update = BatchTreeUpdate {
            operations: vec![
                WriteOp::Update { index: 2 },
                WriteOp::Update { index: 4 },
                WriteOp::Update { index: 5 },
            ],
            entries: vec![
                (k_sender, AccountProperties::hash(&sender_after)),
                (k_coinbase, AccountProperties::hash(&coinbase_after)),
                (k_c_slot0, true_p),
            ],
            sorted_leaves: leaves.clone(),
            intermediate_hashes: vec![],
            leaf_count_before: 6,
        };
        let interop_proofs = Some(interop_proofs_nonsettlement(&tree_update));

        // `blocks[1]` carries the variable historical hash for block 3.
        let build = |slot_p_in_block1: B256| -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 1,
                spec_id: 2,
                protocol_version_minor: 31,
                batch_meta: BatchMeta {
                    tree_root_before: root,
                    leaf_count_before: 6,
                    block_number_before: BNB,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: server_pinned,
                    previous_block_hashes: vec![],
                    upgrade_tx_hash: B256::ZERO,
                    da_commitment_scheme: 2,
                    pubdata: vec![],
                    multichain_root: B256::ZERO,
                    sl_chain_id: 0,
                    blob_versioned_hashes: vec![],
                    tree_update: Some(tree_update.clone()),
                    account_preimages_after: vec![
                        (sender, sender_after.clone()),
                        (coinbase, coinbase_after.clone()),
                    ],
                    fri_proof_verification_enabled: false,
                    max_tx_gas_limit: 1 << 24,
                    interop_proofs: interop_proofs.clone(),
                },
                blocks: vec![
                    BlockInput {
                        number: FIRST,
                        timestamp: 1700000000,
                        base_fee: 7,
                        gas_limit: 80_000_000,
                        coinbase,
                        prev_randao: B256::from([1u8; 32]),
                        block_header_hash: B256::ZERO,
                        storage_proofs: vec![
                            (k_sender, existing(2)),
                            (k_c, existing(3)),
                            (k_coinbase, existing(4)),
                            (k_c_slot0, existing(5)),
                        ],
                        account_preimages: vec![
                            (sender, sender_props.clone()),
                            (c_addr, c_props.clone()),
                            (coinbase, coinbase_props.clone()),
                        ],
                        transactions: vec![TxInput {
                            chain_id: Some(1),
                            gas_used_override: Some(GAS_USED),
                            force_fail: false,
                            auth: TxAuth::L2 { signed_bytes: signed.clone() },
                        }],
                        block_hashes: history.clone(),
                        l2_to_l1_logs: vec![],
                        expected_tree_root: B256::ZERO,
                    },
                    BlockInput {
                        number: LAST,
                        timestamp: 1700000001,
                        base_fee: 7,
                        gas_limit: 80_000_000,
                        coinbase,
                        prev_randao: B256::from([1u8; 32]),
                        block_header_hash: B256::ZERO,
                        storage_proofs: vec![],
                        account_preimages: vec![],
                        transactions: vec![],
                        block_hashes: vec![(P, slot_p_in_block1)],
                        l2_to_l1_logs: vec![],
                        expected_tree_root: B256::ZERO,
                    },
                ],
                bytecodes: vec![(alloy_primitives::keccak256(&c_code), c_code.clone())],
            }
        };

        // Honest: blocks[1] carries the true hash. A successful commit proves
        // BLOCKHASH(3) returned the authenticated value (the SSTORE matches the
        // tree_update entry, else verify_tree_update would reject it).
        let (out, c_honest) = executor::execute_and_commit(&build(true_p));
        assert!(out.block_results[0].tx_results[0].success, "contract call must succeed");

        // Forged: blocks[1] injects a different hash for block 3. The map still
        // resolves BLOCKHASH(3) from the authenticated before-ring, so the stored
        // value is unchanged and the commitment is identical.
        let forged = B256::repeat_byte(0xEE);
        assert_ne!(forged, true_p);
        let (_out2, c_forged) = executor::execute_and_commit(&build(forged));
        assert_eq!(
            c_honest, c_forged,
            "a later block's forged historical hash must not change BLOCKHASH \
             (the map is built from the authenticated before-ring)"
        );
    }

    // ========== write-set completeness & reconciliation ==========

    /// Honest single-block batch: a legacy self-transfer that debits `sender` a
    /// 21000*10 gas fee (nonce 0->1) and credits `coinbase`, over a 4-leaf dense
    /// tree (MIN/MAX guards + sender + coinbase). Both changed accounts are
    /// covered by an after-preimage and a matching `tree_update` Update. Callers
    /// clone the result and tamper one field to exercise the reconciliation
    /// guards. Returns (batch, sender, coinbase, k_sender, k_coinbase,
    /// sender_after, coinbase_after).
    #[allow(clippy::type_complexity)]
    fn honest_transfer_batch(
    ) -> (BatchInput, Address, Address, B256, B256, Vec<u8>, Vec<u8>) {
        const GAS_PRICE: u64 = 10;
        const GAS_USED: u64 = 21_000;
        let sender_balance_before = U256::from(1_000_000_000_000_000_000u128);
        let coinbase_balance_before = U256::from(5u64);
        let fee = U256::from(GAS_USED) * U256::from(GAS_PRICE as u128);

        // Derive the sender from the fixed key, then sign a self-transfer to it.
        let (sender, _) = sign_legacy([0x42u8; 32], 0, Address::ZERO, vec![], 100_000);
        let (_, signed_bytes) = sign_legacy([0x42u8; 32], 0, sender, vec![], 100_000);
        let coinbase: Address =
            "0x00000000000000000000000000000000c01badde".parse().unwrap();

        let sender_props = encode_account_props(0, sender_balance_before);
        let coinbase_props = encode_account_props(0, coinbase_balance_before);
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
        ]);
        let proof_for = |idx: usize| -> StorageProof {
            let (i, leaf) = &leaves[idx];
            StorageProof::Existing(SlotProofEntry {
                index: *i,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx].clone(),
            })
        };

        let sender_after = encode_account_props(1, sender_balance_before - fee);
        let coinbase_after = encode_account_props(0, coinbase_balance_before + fee);

        let tree_update = BatchTreeUpdate {
            operations: vec![WriteOp::Update { index: 2 }, WriteOp::Update { index: 3 }],
            entries: vec![
                (k_sender, AccountProperties::hash(&sender_after)),
                (k_coinbase, AccountProperties::hash(&coinbase_after)),
            ],
            sorted_leaves: leaves.clone(),
            intermediate_hashes: vec![],
            leaf_count_before: 4,
        };
        let interop_proofs = Some(interop_proofs_nonsettlement(&tree_update));

        let batch = BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 1,
            spec_id: 2,
            protocol_version_minor: 31,
            batch_meta: BatchMeta {
                tree_root_before: root,
                leaf_count_before: 4,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: empty_ring_blake(),
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 1,
                blob_versioned_hashes: vec![],
                tree_update: Some(tree_update),
                account_preimages_after: vec![
                    (sender, sender_after.clone()),
                    (coinbase, coinbase_after.clone()),
                ],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
                interop_proofs,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 7,
                gas_limit: 1_000_000,
                coinbase,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(k_sender, proof_for(2)), (k_coinbase, proof_for(3))],
                account_preimages: vec![
                    (sender, sender_props.clone()),
                    (coinbase, coinbase_props.clone()),
                ],
                transactions: vec![TxInput {
                    chain_id: Some(1),
                    gas_used_override: Some(GAS_USED),
                    force_fail: false,
                    auth: TxAuth::L2 { signed_bytes: signed_bytes.clone() },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };
        (batch, sender, coinbase, k_sender, k_coinbase, sender_after, coinbase_after)
    }

    // ================= interop-scalar derivation =================

    /// A/B (non-settlement layer): the guest now DERIVES `sl_chain_id` and
    /// `multichain_root` from the authenticated slot proofs, so the witness
    /// SCALARS no longer feed the commitment. Forging either scalar must leave
    /// the commitment byte-identical (proof that they are no longer trusted),
    /// and this equals "today's" commitment because the derived values (0, 0)
    /// match what a non-settlement chain's scalars held.
    #[test]
    fn interop_scalars_not_trusted_and_commitment_stable() {
        let (honest, ..) = honest_transfer_batch();
        let (_o, c_honest) = executor::execute_and_commit(&honest);

        // Forge BOTH witness scalars; the commitment must be unchanged.
        let mut scalar_forged = honest.clone();
        scalar_forged.batch_meta.sl_chain_id = 0xdead_beef;
        scalar_forged.batch_meta.multichain_root = B256::repeat_byte(0xAB);
        let (_o2, c_forged) = executor::execute_and_commit(&scalar_forged);
        assert_eq!(
            c_honest, c_forged,
            "interop witness scalars must not affect the commitment (now derived from proofs)"
        );
    }

    /// A forged interop PROOF (value inconsistent with the pinned tree root) is
    /// rejected end to end — the derived scalar rests on the merkle proof, not
    /// on trust.
    #[test]
    fn interop_forged_slot_proof_rejected() {
        let (honest, ..) = honest_transfer_batch();

        // Corrupt the sl_chain_id proof so its neighbors recover different roots.
        let mut sl_forged = honest.clone();
        if let Some(p) = sl_forged.batch_meta.interop_proofs.as_mut() {
            if let StorageProof::NonExisting { left_neighbor, .. } = &mut p.sl_chain_id {
                left_neighbor.entry.value = B256::repeat_byte(0x99);
            }
        }
        assert!(
            std::panic::catch_unwind(|| executor::execute_and_commit(&sl_forged)).is_err(),
            "a forged sl_chain_id slot proof must be rejected"
        );

        // Corrupt the multichain-root proof likewise.
        let mut mc_forged = honest.clone();
        if let Some(p) = mc_forged.batch_meta.interop_proofs.as_mut() {
            if let StorageProof::NonExisting { left_neighbor, .. } = &mut p.multichain_root {
                left_neighbor.entry.value = B256::repeat_byte(0x99);
            }
        }
        assert!(
            std::panic::catch_unwind(|| executor::execute_and_commit(&mc_forged)).is_err(),
            "a forged multichain_root slot proof must be rejected"
        );
    }

    /// A/B (settlement layer): a v31 batch whose post-state tree holds the
    /// MessageRoot `0x10005` aggregation slots (height `H`, `nodes[H][0]=R`)
    /// derives `multichain_root = R`. The scalar is again irrelevant: forging it
    /// leaves the commitment unchanged, and dropping the aggregation root from
    /// the tree changes the commitment (so the derived value genuinely feeds it).
    #[test]
    fn interop_settlement_layer_multichain_derived_from_slots() {
        // A no-write batch: one empty block, tree_update None, so
        // tree_root_after == tree_root_before. The pre-state tree carries the
        // 0x10005 aggregation slots plus the block's coinbase account.
        let coinbase: Address = "0x00000000000000000000000000000000c01badde".parse().unwrap();
        let coinbase_props = encode_account_props(0, U256::from(5u64));
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());

        const MESSAGE_ROOT_ADDR: [u8; 20] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x05,
        ];
        let height = B256::with_last_byte(4);
        let agg_root = B256::repeat_byte(0xC3);
        let height_key = derive_flat_storage_key(&MESSAGE_ROOT_ADDR, &B256::with_last_byte(0x04));
        // nodes[4][0] slot = keccak256( keccak256(word(0x06)) + 4 ).
        let base = U256::from_be_bytes(
            crate::hash::keccak256(B256::with_last_byte(0x06).as_slice()).0,
        );
        let node_slot_word = base.wrapping_add(U256::from(4u64));
        let root_slot = crate::hash::keccak256(&node_slot_word.to_be_bytes::<32>());
        let root_key = derive_flat_storage_key(&MESSAGE_ROOT_ADDR, &root_slot);

        let (root, leaves, siblings) = build_dense_tree(&[
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
            (height_key, height),
            (root_key, agg_root),
        ]);
        let existing_for = |key: &B256| -> StorageProof {
            let (i, leaf) = leaves.iter().find(|(_, l)| l.key == *key).unwrap();
            StorageProof::Existing(SlotProofEntry {
                index: *i,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[*i as usize].clone(),
            })
        };
        let (sl_key, _, _) = interop_slot_keys();

        let build = |scalar_multichain: B256| -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 1,
                spec_id: 2,
                protocol_version_minor: 31,
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
                    multichain_root: scalar_multichain,
                    sl_chain_id: 7,
                    blob_versioned_hashes: vec![],
                    tree_update: None,
                    account_preimages_after: vec![],
                    fri_proof_verification_enabled: false,
                    max_tx_gas_limit: 1 << 24,
                    interop_proofs: Some(InteropSlotProofs {
                        // No writes => tree_root_after == tree_root_before, so all
                        // three proofs verify against `root`.
                        sl_chain_id: non_existence_proof(&leaves, &siblings, &sl_key),
                        multichain_height: existing_for(&height_key),
                        multichain_root: existing_for(&root_key),
                    }),
                },
                blocks: vec![BlockInput {
                    number: 1,
                    timestamp: 1700000000,
                    base_fee: 7,
                    gas_limit: 1_000_000,
                    coinbase,
                    prev_randao: B256::from([1u8; 32]),
                    block_header_hash: B256::ZERO,
                    storage_proofs: vec![(k_coinbase, existing_for(&k_coinbase))],
                    account_preimages: vec![(coinbase, coinbase_props.clone())],
                    transactions: vec![],
                    block_hashes: vec![],
                    l2_to_l1_logs: vec![],
                    expected_tree_root: B256::ZERO,
                }],
                bytecodes: vec![],
            }
        };

        // Honest and scalar-forged batches produce the SAME commitment: the
        // multichain root is derived from the proven slot, not the scalar.
        let (_o, c_zero_scalar) = executor::execute_and_commit(&build(B256::ZERO));
        let (_o2, c_bogus_scalar) = executor::execute_and_commit(&build(B256::repeat_byte(0x11)));
        assert_eq!(
            c_zero_scalar, c_bogus_scalar,
            "settlement-layer multichain_root is derived, not taken from the scalar"
        );
    }

    /// A duplicated `tree_update.entries` key inflates `.len()` to match
    /// `revm_writes` while the forward pass silently drops a genuine write
    /// (coinbase's credit). The dedup assert rejects it; the honest batch (with
    /// distinct keys) still passes and its commitment is unchanged.
    #[test]
    fn duplicate_tree_update_key_rejected() {
        let (honest, _s, _c, k_sender, _kc, sender_after, _ca) = honest_transfer_batch();
        // Honest passes.
        let (out, _c) = executor::execute_and_commit(&honest);
        assert!(out.block_results[0].tx_results[0].success);

        // Forge: duplicate k_sender (dropping k_coinbase). Two entries, two ops,
        // len still 2 == revm_writes.len(); before the fix the forward pass
        // never examined k_coinbase and its leaf kept the stale pre-state value.
        let mut forged = honest.clone();
        let tu = forged.batch_meta.tree_update.as_mut().unwrap();
        tu.operations = vec![WriteOp::Update { index: 2 }, WriteOp::Update { index: 2 }];
        tu.entries = vec![
            (k_sender, AccountProperties::hash(&sender_after)),
            (k_sender, AccountProperties::hash(&sender_after)),
        ];
        let rejected = std::panic::catch_unwind(|| executor::execute_and_commit(&forged));
        assert!(
            rejected.is_err(),
            "duplicate-key tree_update (dropping a real write) must be rejected"
        );
    }

    /// `apply` walks `operations.iter().zip(&entries)`, stopping at the shorter
    /// vector. A truncated `operations` therefore drops the trailing writes: the
    /// pinned old root still matches, but the applied `tree_root_after` silently
    /// omits them. The length assert rejects it; the honest batch (equal lengths)
    /// still passes.
    #[test]
    fn truncated_tree_update_operations_rejected() {
        // Recast the honest transfer batch as v30 so `tree_root_after` is not
        // independently pinned by the interop post-state proofs. The length
        // assert is then the only check standing between a truncated operations
        // vector and a silently wrong applied root.
        let (honest_v31, ..) = honest_transfer_batch();
        let mut honest = honest_v31.clone();
        honest.spec_id = 1; // AtlasV2
        honest.protocol_version_minor = 30;
        honest.batch_meta.interop_proofs = None;
        // Honest passes: two operations for two entries.
        let (out, _c) = executor::execute_and_commit(&honest);
        assert!(out.block_results[0].tx_results[0].success);

        // Forge: keep both (correct) entries, drop the coinbase operation. `apply`
        // then zips only the sender operation and leaves the coinbase leaf stale;
        // the pinned old root still matches, so the applied `tree_root_after` is
        // silently wrong. Only the length assert rejects it.
        let mut forged = honest.clone();
        let tu = forged.batch_meta.tree_update.as_mut().unwrap();
        assert_eq!(tu.operations.len(), 2);
        assert_eq!(tu.entries.len(), 2);
        tu.operations.truncate(1);
        let rejected = std::panic::catch_unwind(|| executor::execute_and_commit(&forged));
        assert!(
            rejected.is_err(),
            "truncated operations (fewer than entries) must be rejected"
        );
    }

    /// Injection: an after-preimage for an account REVM never executed,
    /// in a normal (non-upgrade) batch, is a fabricated write (minting a balance
    /// onto a dormant EOA). The injection guard rejects it.
    #[test]
    fn inject_untouched_eoa_rejected() {
        let (honest, _s, _c, _ks, _kc, _sa, _ca) = honest_transfer_batch();
        let _ = executor::execute_and_commit(&honest);

        let dormant: Address =
            "0x00000000000000000000000000000000deadbeef".parse().unwrap();
        // Inflated balance minted onto an account no transaction touched.
        let dormant_after = encode_account_props(0, U256::from(9_999_999_999u64));

        let mut forged = honest.clone();
        forged
            .batch_meta
            .account_preimages_after
            .push((dormant, dormant_after));
        let rejected = std::panic::catch_unwind(|| executor::execute_and_commit(&forged));
        assert!(
            rejected.is_err(),
            "after-preimage for a non-executed account in a normal batch must be rejected"
        );
    }

    /// Omission: a batch that credits `coinbase` but omits it from BOTH
    /// `account_preimages_after` and `tree_update`: the write-set stays
    /// internally consistent (1 write each), so the pre-fix set-equality passed
    /// and `state_after` silently dropped coinbase's credit. The completeness
    /// check now flags the REVM-changed account.
    #[test]
    fn omit_changed_account_rejected() {
        let (honest, sender, _c, k_sender, _kc, sender_after, _ca) = honest_transfer_batch();
        let _ = executor::execute_and_commit(&honest);

        let mut forged = honest.clone();
        // Keep only sender's after-preimage and tree write; drop coinbase's.
        forged.batch_meta.account_preimages_after = vec![(sender, sender_after.clone())];
        let tu = forged.batch_meta.tree_update.as_mut().unwrap();
        tu.operations = vec![WriteOp::Update { index: 2 }];
        tu.entries = vec![(k_sender, AccountProperties::hash(&sender_after))];
        let rejected = std::panic::catch_unwind(|| executor::execute_and_commit(&forged));
        assert!(
            rejected.is_err(),
            "omitting a REVM-changed account (coinbase credit) must be rejected"
        );
    }

    /// The injection guard OPENS for upgrade batches, the sanctioned
    /// force-deploy / system path (a documented trusted hole). An Upgrade tx is
    /// present (so `upgrade_tx_hash` is authenticated nonzero), and a
    /// non-executed account carries an after-preimage plus a matching tree
    /// write. This honest force-deploy-style batch passes.
    #[test]
    fn upgrade_batch_allows_non_executed_after_preimage() {
        // Caller of the (force-failed) Upgrade tx.
        let sender: Address =
            "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address =
            "0x2000000000000000000000000000000000000002".parse().unwrap();
        // Force-deployed target: no transaction touches it; the upgrade sets its
        // account properties directly (represented here by nonce/balance).
        let fd: Address = "0x000000000000000000000000000000000000800f".parse().unwrap();

        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let fd_props_old = encode_account_props(0, U256::ZERO);
        let fd_after = encode_account_props(1, U256::from(42u64));
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_fd = derive_account_properties_key(&fd.into_array());
        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_fd, AccountProperties::hash(&fd_props_old)),
        ]);
        let proof_for = |idx: usize| -> StorageProof {
            let (i, leaf) = &leaves[idx];
            StorageProof::Existing(SlotProofEntry {
                index: *i,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx].clone(),
            })
        };

        // Upgrade tx (type 0x7e), force-failed so no execution-side state change.
        let upgrade_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20;
            abi[32 + 31] = 0x7e; // txType = upgrade
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice()); // from
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice()); // to
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes()); // gas
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice()); // refund
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let upgrade_tx_hash = alloy_primitives::keccak256(&upgrade_abi);

        let batch = BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: root,
                leaf_count_before: 4,
                block_number_before: 0,
                last_block_timestamp_before: 0,
                block_hashes_blake_before: empty_ring_blake(),
                previous_block_hashes: vec![],
                upgrade_tx_hash,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0,
                blob_versioned_hashes: vec![],
                tree_update: Some(BatchTreeUpdate {
                    operations: vec![WriteOp::Update { index: 3 }],
                    entries: vec![(k_fd, AccountProperties::hash(&fd_after))],
                    sorted_leaves: leaves.clone(),
                    intermediate_hashes: vec![],
                    leaf_count_before: 4,
                }),
                // Non-executed force-deploy target: accepted because this is an
                // upgrade batch.
                account_preimages_after: vec![(fd, fd_after.clone())],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit: 1 << 24,
                interop_proofs: None,
            },
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs: vec![(k_sender, proof_for(2))],
                account_preimages: vec![(sender, sender_props.clone())],
                transactions: vec![TxInput {
                    chain_id: Some(270),
                    gas_used_override: Some(0),
                    force_fail: true,
                    auth: TxAuth::Upgrade {
                        tx_hash: upgrade_tx_hash,
                        abi_encoded: upgrade_abi.clone(),
                    },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        };

        // Honest upgrade batch with a non-executed force-deploy write: passes.
        let (_out, commitment) = executor::execute_and_commit(&batch);
        assert_ne!(commitment, B256::ZERO, "honest upgrade batch must commit");
    }

    /// Fix: `sl_chain_id` is derived from the authenticated post-state slot for
    /// EVERY v31 batch, including upgrade batches (which previously inherited the
    /// witness scalar). Forging `meta.sl_chain_id` on an upgrade batch must leave
    /// the commitment unchanged, proving the scalar no longer feeds it.
    #[test]
    fn upgrade_batch_sl_chain_id_derived_not_inherited() {
        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        // Non-executed force-deploy target (the sanctioned upgrade hole).
        let fd: Address = "0x000000000000000000000000000000000000800f".parse().unwrap();

        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let fd_props_old = encode_account_props(0, U256::ZERO);
        let fd_after = encode_account_props(1, U256::from(42u64));
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_fd = derive_account_properties_key(&fd.into_array());
        let (root, leaves, siblings) = build_dense_tree(&[
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_fd, AccountProperties::hash(&fd_props_old)),
        ]);
        let proof_for = |idx: usize| -> StorageProof {
            let (i, leaf) = &leaves[idx];
            StorageProof::Existing(SlotProofEntry {
                index: *i,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx].clone(),
            })
        };

        // Upgrade tx (type 0x7e), force-failed so there is no execution-side change.
        let upgrade_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20;
            abi[32 + 31] = 0x7e;
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice());
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice());
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes());
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice());
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let upgrade_tx_hash = alloy_primitives::keccak256(&upgrade_abi);

        let tree_update = BatchTreeUpdate {
            operations: vec![WriteOp::Update { index: 3 }],
            entries: vec![(k_fd, AccountProperties::hash(&fd_after))],
            sorted_leaves: leaves.clone(),
            intermediate_hashes: vec![],
            leaf_count_before: 4,
        };
        // Non-settlement interop proofs: sl_chain_id derives to 0 from the
        // authenticated post-state slot (NonExisting), independent of the scalar.
        let interop_proofs = Some(interop_proofs_nonsettlement(&tree_update));

        let build = |scalar: u64| -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 270,
                spec_id: 2, // AtlasV3 (v31)
                protocol_version_minor: 31,
                batch_meta: BatchMeta {
                    tree_root_before: root,
                    leaf_count_before: 4,
                    block_number_before: 0,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: empty_ring_blake(),
                    previous_block_hashes: vec![],
                    upgrade_tx_hash,
                    da_commitment_scheme: 2,
                    pubdata: vec![],
                    multichain_root: B256::ZERO,
                    sl_chain_id: scalar,
                    blob_versioned_hashes: vec![],
                    tree_update: Some(tree_update.clone()),
                    account_preimages_after: vec![(fd, fd_after.clone())],
                    fri_proof_verification_enabled: false,
                    max_tx_gas_limit: 1 << 24,
                    interop_proofs: interop_proofs.clone(),
                },
                blocks: vec![BlockInput {
                    number: 1,
                    timestamp: 1700000000,
                    base_fee: 250_000_000,
                    gas_limit: 80_000_000,
                    coinbase: sender,
                    prev_randao: B256::from([1u8; 32]),
                    block_header_hash: B256::ZERO,
                    storage_proofs: vec![(k_sender, proof_for(2))],
                    account_preimages: vec![(sender, sender_props.clone())],
                    transactions: vec![TxInput {
                        chain_id: Some(270),
                        gas_used_override: Some(0),
                        force_fail: true,
                        auth: TxAuth::Upgrade {
                            tx_hash: upgrade_tx_hash,
                            abi_encoded: upgrade_abi.clone(),
                        },
                    }],
                    block_hashes: vec![],
                    l2_to_l1_logs: vec![],
                    expected_tree_root: B256::ZERO,
                }],
                bytecodes: vec![],
            }
        };

        // Honest and forged scalars must commit to the SAME value: the derived
        // sl_chain_id comes from the post-state proof, not from meta.sl_chain_id.
        let (_o1, c_honest) = executor::execute_and_commit(&build(0));
        let (_o2, c_forged) = executor::execute_and_commit(&build(0xdead_beef));
        assert_eq!(
            c_honest, c_forged,
            "upgrade-batch sl_chain_id must be derived from the post-state proof, \
             not inherited from the witness scalar"
        );
    }

    // ======================= Streaming deserialize =======================

    /// The streaming entry point (`execute_and_commit_streaming`, guest path)
    /// must produce a byte-identical commitment AND output to the collecting
    /// entry point (`execute_and_commit_from_bincode`, server path), from the
    /// same server-serialized bytes. This is the A/B commitment-equality check.
    fn assert_ab_streaming_matches(input: &BatchInput) {
        let bytes = crate::wire::encode(input).unwrap();
        let (out_a, c_a) = executor::execute_and_commit_from_bincode(&bytes).unwrap();
        let (out_b, c_b) = executor::execute_and_commit_streaming(&bytes).unwrap();
        assert_eq!(c_a, c_b, "streaming commitment != collecting commitment");
        assert_eq!(
            crate::wire::encode(&out_a).unwrap(),
            crate::wire::encode(&out_b).unwrap(),
            "streaming BatchOutput != collecting BatchOutput"
        );
    }

    /// Read-spam batch: N distinct cold storage slots (each with a valid
    /// depth-64 Existing proof) plus the sender account, driven by a single
    /// `force_fail` L1 tx so execution is trivial and the witness (all the
    /// merkle siblings) dominates. Models the read-spam OOM vector.
    fn read_spam_batch(n_slots: usize) -> BatchInput {
        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let sender_flat = derive_account_properties_key(&sender.into_array());

        let mut data: Vec<(B256, B256)> = Vec::with_capacity(n_slots + 1);
        data.push((sender_flat, AccountProperties::hash(&sender_props)));
        let some_addr = [0x11u8; 20];
        for i in 0..n_slots {
            let mut slot = [0u8; 32];
            slot[24..32].copy_from_slice(&(i as u64).to_be_bytes());
            let fk = derive_flat_storage_key(&some_addr, &B256::from(slot));
            data.push((fk, B256::repeat_byte((i % 251) as u8 + 1)));
        }
        let (root, leaves, siblings) = build_dense_tree(&data);

        let proof_for = |leaf_idx: usize| -> StorageProof {
            let (idx, leaf) = &leaves[leaf_idx];
            StorageProof::Existing(SlotProofEntry {
                index: *idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[leaf_idx].clone(),
            })
        };
        // data[j] lives at leaves[j + 2] (0,1 are the MIN/MAX guards).
        let mut storage_proofs = Vec::with_capacity(n_slots + 1);
        for (j, (k, _)) in data.iter().enumerate() {
            storage_proofs.push((*k, proof_for(j + 2)));
        }

        let l1_abi = {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20;
            abi[32 + 31] = 0x7f;
            abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice());
            abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice());
            abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes());
            abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
            abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice());
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            abi
        };
        let l1_tx_hash = alloy_primitives::keccak256(&l1_abi);

        BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 270,
            spec_id: 1,
            protocol_version_minor: 30,
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
            blocks: vec![BlockInput {
                number: 1,
                timestamp: 1700000000,
                base_fee: 250_000_000,
                gas_limit: 80_000_000,
                coinbase: sender,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash: B256::ZERO,
                storage_proofs,
                account_preimages: vec![(sender, sender_props)],
                transactions: vec![TxInput {
                    chain_id: Some(270),
                    gas_used_override: Some(0),
                    force_fail: true,
                    auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                }],
                block_hashes: vec![],
                l2_to_l1_logs: vec![L2ToL1LogEntry {
                    l2_shard_id: 0,
                    is_service: true,
                    tx_number_in_block: 0,
                    sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                    key: l1_tx_hash,
                    value: B256::ZERO,
                }],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        }
    }

    #[test]
    fn stream_ab_read_spam_5k() {
        assert_ab_streaming_matches(&read_spam_batch(5_000));
    }

    #[test]
    fn stream_ab_read_spam_20k() {
        assert_ab_streaming_matches(&read_spam_batch(20_000));
    }

    /// Heavier scale, kept out of the default run for speed; enable with
    /// `--ignored`. Confirms A/B equality holds at 50k slots.
    #[test]
    #[ignore = "heavy: 50k proofs; run explicitly for the scale check"]
    fn stream_ab_read_spam_50k() {
        assert_ab_streaming_matches(&read_spam_batch(50_000));
    }

    // ================== read-authentication root (soundness) ==================
    //
    // Every storage/account read must be authenticated against the single
    // L1-pinned pre-state root `meta.tree_root_before`, NEVER against the witness
    // scalar `block.expected_tree_root`. Before the fix, `expected_root_for_block`
    // returned `block.expected_tree_root` verbatim whenever it was non-zero, so an
    // operator could point read-authentication at a FABRICATED tree, serve
    // attacker-chosen pre-state values, and fold the resulting execution into a
    // commitment native never produces. The fix ignores the witness field for
    // authentication (always uses `tree_root_before`) and rejects up front any
    // block whose `expected_tree_root` is neither zero nor `tree_root_before`.

    /// ABI-encoded L2CanonicalTransaction for the force_fail L1 txs below (mirrors
    /// the inline encoder used by the block-hash tests). force_fail + gas 0 drives
    /// the full commit path without writes, so the commitment completes without
    /// the tree_update the review's drain scenario would additionally require.
    fn force_fail_l1_abi(from: Address, to: Address) -> (Vec<u8>, B256) {
        let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
        abi[31] = 0x20;
        abi[32 + 31] = 0x7f;
        abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(from.as_slice());
        abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(to.as_slice());
        abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes());
        abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes());
        abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(from.as_slice());
        let dyn_base = 19u32 * 32;
        for j in 0..5u32 {
            let off = 32 + (14 + j as usize) * 32;
            abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
        }
        let hash = alloy_primitives::keccak256(&abi);
        (abi, hash)
    }

    /// Read-authentication root (single block): reject a batch whose
    /// `blocks[0].expected_tree_root`
    /// differs from the L1-pinned `meta.tree_root_before`, even when the block
    /// ships fabricated-but-self-consistent proofs that recover that forged root.
    ///
    /// Two trees over the SAME sender key: the REAL tree (10 ETH, root pinned as
    /// `tree_root_before`) and a FABRICATED tree (a privileged 10^24 balance, a
    /// different root). The forged batch points read-authentication at the
    /// fabricated root and proves the sender's account against it. Before the fix
    /// this was ACCEPTED (every read authenticated against a tree the guest never
    /// tied to L1); after the fix the forged read root is rejected on both the
    /// collecting and the streaming/ELF path, while the honest control commits.
    #[test]
    fn forged_block0_read_root_rejected() {
        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let sender_flat_key = derive_account_properties_key(&sender.into_array());

        let real_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let fake_props =
            encode_account_props(0, U256::from(1_000_000_000_000_000_000_000_000u128));
        let real_hash = AccountProperties::hash(&real_props);
        let fake_hash = AccountProperties::hash(&fake_props);
        assert_ne!(real_hash, fake_hash, "the fabricated balance must differ");

        let (r_real, lc, real_sib) = build_minimal_tree(&sender_flat_key, &real_hash);
        let (r_fake, _lc2, fake_sib) = build_minimal_tree(&sender_flat_key, &fake_hash);
        assert_ne!(r_real, r_fake, "the fabricated tree must have a different root");

        let (l1_abi, l1_tx_hash) = force_fail_l1_abi(sender, recipient);

        let build = |expected_tree_root: B256, value: B256, sib: Vec<B256>, preimage: Vec<u8>| -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 270,
                spec_id: 1,
                protocol_version_minor: 30,
                batch_meta: BatchMeta {
                    tree_root_before: r_real,
                    leaf_count_before: lc,
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
                blocks: vec![BlockInput {
                    number: 1,
                    timestamp: 1700000000,
                    base_fee: 250_000_000,
                    gas_limit: 80_000_000,
                    coinbase: sender,
                    prev_randao: B256::from([1u8; 32]),
                    block_header_hash: B256::ZERO,
                    storage_proofs: vec![(
                        sender_flat_key,
                        StorageProof::Existing(SlotProofEntry {
                            index: 2,
                            value,
                            next_index: 1,
                            siblings: sib,
                        }),
                    )],
                    account_preimages: vec![(sender, preimage)],
                    transactions: vec![TxInput {
                        chain_id: Some(270),
                        gas_used_override: Some(0),
                        force_fail: true,
                        auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                    }],
                    block_hashes: vec![],
                    l2_to_l1_logs: vec![L2ToL1LogEntry {
                        l2_shard_id: 0,
                        is_service: true,
                        tx_number_in_block: 0,
                        sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                        key: l1_tx_hash,
                        value: B256::ZERO,
                    }],
                    expected_tree_root,
                }],
                bytecodes: vec![],
            }
        };

        // Honest control: read root == pinned tree_root_before (encoded as the
        // zero sentinel), real proof + preimage. Proves the harness is valid.
        let honest = build(B256::ZERO, real_hash, real_sib.clone(), real_props.clone());
        let (_o, c_honest) = executor::execute_and_commit(&honest);
        assert_ne!(c_honest, B256::ZERO, "honest batch must commit");

        // Forged: read root = the fabricated tree; proof + preimage self-consistent
        // with it. Collecting path must reject.
        let forged = build(r_fake, fake_hash, fake_sib, fake_props);
        let rejected = std::panic::catch_unwind(|| executor::execute_and_commit(&forged));
        assert!(
            rejected.is_err(),
            "a block whose expected_tree_root != tree_root_before (with proofs \
             recovering the forged root) must be rejected on the collecting path"
        );

        // Streaming/ELF path must reject too (Ok(Ok(_)) would mean it committed).
        let forged_bytes = crate::wire::encode(&forged).unwrap();
        let rejected_stream =
            std::panic::catch_unwind(|| executor::execute_and_commit_streaming(&forged_bytes));
        assert!(
            !matches!(rejected_stream, Ok(Ok(_))),
            "the streaming path must also reject the forged read root"
        );
    }

    /// Read-authentication root (multi-block): reject a batch whose LATER block
    /// carries a forged
    /// `expected_tree_root`. Block 1 is honest (reads against `tree_root_before`);
    /// block 2 proves a slot `J` against a fabricated root. Before the fix that
    /// later-block read root was trusted verbatim (an unauthenticated
    /// intermediate root), so block 2's reads authenticated against a tree never
    /// chained to L1; after the fix it is rejected on both paths. The honest
    /// control proves `J` against the pinned `tree_root_before` — which the fix's
    /// single-root read model requires — so it still commits.
    #[test]
    fn forged_later_block_read_root_rejected() {
        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let contract: Address = "0x00000000000000000000000000000000c0de0002".parse().unwrap();
        let sender_flat_key = derive_account_properties_key(&sender.into_array());

        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let sender_hash = AccountProperties::hash(&sender_props);

        // `J` is a fresh slot present in BOTH trees. The real tree pins
        // `tree_root_before`; the fabricated tree holds a DIFFERENT value for `J`
        // (hence a different root). Both trees carry the sender leaf too, so
        // block 1's honest read is valid against either tree's sibling set.
        let j_key = derive_flat_storage_key(&contract.into_array(), &B256::with_last_byte(7));
        let j_real = B256::repeat_byte(0x77);
        let j_fake = B256::repeat_byte(0x99);
        let (r_real, leaves_real, sib_real) =
            build_dense_tree(&[(sender_flat_key, sender_hash), (j_key, j_real)]);
        let (r_forged, leaves_fake, sib_fake) =
            build_dense_tree(&[(sender_flat_key, sender_hash), (j_key, j_fake)]);
        assert_ne!(r_real, r_forged, "fabricated later-block tree must differ");

        // sender is data leaf 0 (index 2), J is data leaf 1 (index 3).
        let existing = |leaves: &[(u64, TreeLeaf)], sib: &[Vec<B256>], idx: u64| -> StorageProof {
            let (_, leaf) = &leaves[idx as usize];
            StorageProof::Existing(SlotProofEntry {
                index: idx,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: sib[idx as usize].clone(),
            })
        };

        let (l1_abi, l1_tx_hash) = force_fail_l1_abi(sender, recipient);

        let build = |block2_expected_root: B256, j_proof: StorageProof| -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 270,
                spec_id: 1,
                protocol_version_minor: 30,
                batch_meta: BatchMeta {
                    tree_root_before: r_real,
                    leaf_count_before: leaves_real.len() as u64,
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
                blocks: vec![
                    // Block 1: honest, reads sender against tree_root_before.
                    BlockInput {
                        number: 1,
                        timestamp: 1700000000,
                        base_fee: 250_000_000,
                        gas_limit: 80_000_000,
                        coinbase: sender,
                        prev_randao: B256::from([1u8; 32]),
                        block_header_hash: B256::ZERO,
                        storage_proofs: vec![(
                            sender_flat_key,
                            existing(&leaves_real, &sib_real, 2),
                        )],
                        account_preimages: vec![(sender, sender_props.clone())],
                        transactions: vec![TxInput {
                            chain_id: Some(270),
                            gas_used_override: Some(0),
                            force_fail: true,
                            auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                        }],
                        block_hashes: vec![],
                        l2_to_l1_logs: vec![L2ToL1LogEntry {
                            l2_shard_id: 0,
                            is_service: true,
                            tx_number_in_block: 0,
                            sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                            key: l1_tx_hash,
                            value: B256::ZERO,
                        }],
                        expected_tree_root: B256::ZERO,
                    },
                    // Block 2: proves fresh slot J against `block2_expected_root`.
                    BlockInput {
                        number: 2,
                        timestamp: 1700000001,
                        base_fee: 250_000_000,
                        gas_limit: 80_000_000,
                        coinbase: sender,
                        prev_randao: B256::from([1u8; 32]),
                        block_header_hash: B256::ZERO,
                        storage_proofs: vec![(j_key, j_proof)],
                        account_preimages: vec![],
                        transactions: vec![],
                        block_hashes: vec![],
                        l2_to_l1_logs: vec![],
                        expected_tree_root: block2_expected_root,
                    },
                ],
                bytecodes: vec![],
            }
        };

        // Honest control: block 2 proves J against the pinned root (zero sentinel).
        let honest = build(B256::ZERO, existing(&leaves_real, &sib_real, 3));
        let (out, c_honest) = executor::execute_and_commit(&honest);
        assert_eq!(out.block_results.len(), 2, "two blocks executed");
        assert_ne!(c_honest, B256::ZERO, "honest multi-block batch must commit");

        // Forged: block 2 points read-authentication at the fabricated tree and
        // proves J against it. Rejected on the collecting path.
        let forged = build(r_forged, existing(&leaves_fake, &sib_fake, 3));
        let rejected = std::panic::catch_unwind(|| executor::execute_and_commit(&forged));
        assert!(
            rejected.is_err(),
            "a later block whose expected_tree_root != tree_root_before must be rejected"
        );

        // ...and on the streaming/ELF path.
        let forged_bytes = crate::wire::encode(&forged).unwrap();
        let rejected_stream =
            std::panic::catch_unwind(|| executor::execute_and_commit_streaming(&forged_bytes));
        assert!(
            !matches!(rejected_stream, Ok(Ok(_))),
            "the streaming path must also reject the forged later-block read root"
        );
    }

    // ==================== first-block parent (soundness) =====================

    /// First-block parent: a duplicate block-number entry in the witness
    /// `block_hashes` must
    /// not inject a forged parent hash for the first block.
    ///
    /// The ring that `block_hashes_blake_before` authenticates is built
    /// last-write-wins, so `(F-1, FORGED) … (F-1, TRUE)` reconstructs to TRUE and
    /// passes the pinned commitment. Before the fix, `evm.rs` read the parent via
    /// a first-match `.find()` over the raw witness and fed FORGED into the block
    /// header hash (and thus into `state_after`). After the fix the parent comes
    /// from the authenticated ring (`before_ring[255]`), so the duplicate is inert
    /// and the forged run commits to the SAME value as the honest run.
    #[test]
    fn duplicate_block_number_cannot_forge_first_parent() {
        use blake2::{Blake2s256, Digest};
        const FIRST: u64 = 6;

        let sender: Address = "0x1000000000000000000000000000000000000001".parse().unwrap();
        let recipient: Address = "0x2000000000000000000000000000000000000002".parse().unwrap();
        let sender_props = encode_account_props(0, U256::from(10_000_000_000_000_000_000u128));
        let sender_props_hash = AccountProperties::hash(&sender_props);
        let sender_flat_key = derive_account_properties_key(&sender.into_array());
        let (tree_root, leaf_count, siblings) =
            build_minimal_tree(&sender_flat_key, &sender_props_hash);

        let (l1_abi, l1_tx_hash) = force_fail_l1_abi(sender, recipient);

        // Honest pre-state history blocks 0..=5; block 5 is the first block's
        // true parent.
        let true_5 = B256::repeat_byte(0x55);
        let forged_5 = B256::repeat_byte(0xEE);
        assert_ne!(true_5, forged_5);
        let mut honest_history: Vec<(u64, B256)> =
            (0..5u64).map(|n| (n, B256::repeat_byte((n as u8) + 0x11))).collect();
        honest_history.push((5, true_5));

        // Pinned commitment: Blake2s over the 256-ring, block 5 at index 255.
        let pinned_blake = {
            let mut ring = [B256::ZERO; 256];
            for &(n, h) in &honest_history {
                ring[(n + 256 - FIRST) as usize] = h;
            }
            let mut hasher = Blake2s256::new();
            for e in &ring {
                hasher.update(e.as_slice());
            }
            B256::from_slice(&hasher.finalize())
        };

        // Forged history: a DUPLICATE (5, forged_5) placed BEFORE (5, true_5).
        // Last-write-wins => the ring still ends in true_5 (auth passes), but a
        // first-match parent lookup would return forged_5.
        let mut forged_history = honest_history.clone();
        forged_history.insert(5, (5, forged_5));

        let build = |block_hashes: Vec<(u64, B256)>| -> BatchInput {
            BatchInput {
                version: crate::types::BATCH_INPUT_VERSION,
                chain_id: 270,
                spec_id: 1,
                protocol_version_minor: 30,
                batch_meta: BatchMeta {
                    tree_root_before: tree_root,
                    leaf_count_before: leaf_count,
                    block_number_before: FIRST - 1,
                    last_block_timestamp_before: 0,
                    block_hashes_blake_before: pinned_blake,
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
                blocks: vec![BlockInput {
                    number: FIRST,
                    timestamp: 1700000000,
                    base_fee: 250_000_000,
                    gas_limit: 80_000_000,
                    coinbase: sender,
                    prev_randao: B256::from([1u8; 32]),
                    block_header_hash: B256::ZERO,
                    storage_proofs: vec![(
                        sender_flat_key,
                        StorageProof::Existing(SlotProofEntry {
                            index: 2,
                            value: sender_props_hash,
                            next_index: 1,
                            siblings: siblings.clone(),
                        }),
                    )],
                    account_preimages: vec![(sender, sender_props.clone())],
                    transactions: vec![TxInput {
                        chain_id: Some(270),
                        gas_used_override: Some(0),
                        force_fail: true,
                        auth: TxAuth::L1 { tx_hash: l1_tx_hash, abi_encoded: l1_abi.clone() },
                    }],
                    block_hashes,
                    l2_to_l1_logs: vec![L2ToL1LogEntry {
                        l2_shard_id: 0,
                        is_service: true,
                        tx_number_in_block: 0,
                        sender: "0x0000000000000000000000000000000000008001".parse().unwrap(),
                        key: l1_tx_hash,
                        value: B256::ZERO,
                    }],
                    expected_tree_root: B256::ZERO,
                }],
                bytecodes: vec![],
            }
        };

        let (_oh, c_honest) = executor::execute_and_commit(&build(honest_history));
        let (_of, c_forged) = executor::execute_and_commit(&build(forged_history));
        assert_ne!(c_honest, B256::ZERO, "honest batch must commit");
        assert_eq!(
            c_honest, c_forged,
            "a duplicate (F-1, FORGED) entry must not change the first block's \
             parent hash: the parent is read from the authenticated ring, not a \
             first-match over the witness block_hashes"
        );
    }

    // ================= AtlasV4 =================

    /// How the EIP-2935 history contract appears in an AtlasV4 batch's
    /// pre-state.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum History {
        /// The witness carries no proof for the account at all.
        Unproven,
        /// A proven-absent account.
        Absent,
        /// An account that holds no code.
        NoCode,
        /// An EIP-7702 delegation designator, which `is_contract()` rejects.
        Delegated,
        /// A deployed contract whose ring slot is empty.
        Contract,
        /// A deployed contract whose ring slot already holds this block's
        /// parent hash.
        ContractSlotAlreadySet,
    }

    /// The EIP-2935 history contract.
    fn history_address() -> Address {
        "0x0000f90827f1c53a10cb7a02335b175320002935".parse().unwrap()
    }

    /// The parent hash of the AtlasV4 fixture's only block. Non-zero, so the
    /// EIP-2935 write is a real state change.
    fn atlas_v4_parent_hash() -> B256 {
        B256::repeat_byte(0x77)
    }

    /// A one-block AtlasV4 batch: block 6 runs one legacy self-transfer that
    /// debits the sender a 21000 * 10 gas fee and credits the coinbase. The
    /// pre-state block-hash ring carries the parent of block 6, so the EIP-2935
    /// write has a non-zero value to store.
    ///
    /// The `history` argument selects how the EIP-2935 history contract appears
    /// in the pre-state, and the `tree_update` follows: only the `Contract` case
    /// adds the ring-slot leaf.
    fn atlas_v4_transfer_batch(history: History) -> BatchInput {
        atlas_v4_transfer_batch_with_limits(history, 1_000_000, 100_000, 1 << 24)
    }

    /// `atlas_v4_transfer_batch` with the three gas bounds spelled out: the
    /// block gas limit, the transaction's own gas limit, and the chain-config
    /// EIP-7825 cap.
    fn atlas_v4_transfer_batch_with_limits(
        history: History,
        block_gas_limit: u64,
        tx_gas_limit: u64,
        max_tx_gas_limit: u64,
    ) -> BatchInput {
        use blake2::{Blake2s256, Digest};

        const GAS_PRICE: u64 = 10;
        const GAS_USED: u64 = 21_000;
        const BLOCK_NUMBER: u64 = 6;
        const TIMESTAMP: u64 = 1_700_000_000;
        const BASE_FEE: u64 = 7;
        const HISTORY_SERVE_WINDOW: u64 = 8191;

        let parent_hash = atlas_v4_parent_hash();
        let history_addr = history_address();
        let sender_balance_before = U256::from(1_000_000_000_000_000_000u128);
        let coinbase_balance_before = U256::from(5u64);
        let fee = U256::from(GAS_USED) * U256::from(GAS_PRICE as u128);

        let (sender, _) = sign_legacy([0x42u8; 32], 0, Address::ZERO, vec![], tx_gas_limit);
        let (_, signed_bytes) = sign_legacy([0x42u8; 32], 0, sender, vec![], tx_gas_limit);
        let coinbase: Address =
            "0x00000000000000000000000000000000c01badde".parse().unwrap();

        let sender_props = encode_account_props(0, sender_balance_before);
        let coinbase_props = encode_account_props(0, coinbase_balance_before);
        let k_sender = derive_account_properties_key(&sender.into_array());
        let k_coinbase = derive_account_properties_key(&coinbase.into_array());
        let k_history = derive_account_properties_key(&history_addr.into_array());
        let slot_index = (BLOCK_NUMBER - 1) % HISTORY_SERVE_WINDOW;
        let slot_key = derive_flat_storage_key(
            &history_addr.into_array(),
            &B256::from(U256::from(slot_index).to_be_bytes::<32>()),
        );

        let history_props = match history {
            History::Unproven | History::Absent => None,
            History::NoCode => Some(encode_account_props(1, U256::ZERO)),
            History::Delegated => {
                let mut designator =
                    crate::account_props::EIP7702_DELEGATION_MARKER.to_vec();
                designator.extend_from_slice(&[0x33u8; 20]);
                Some(encode_account_props_code(1, U256::ZERO, &designator))
            }
            History::Contract | History::ContractSlotAlreadySet => {
                Some(encode_account_props_code(1, U256::ZERO, &[0x5b, 0x00]))
            }
        };

        // Pre-state leaves, in the index order `build_dense_tree` assigns from 2.
        let mut pre_data = vec![
            (k_sender, AccountProperties::hash(&sender_props)),
            (k_coinbase, AccountProperties::hash(&coinbase_props)),
        ];
        if let Some(props) = &history_props {
            pre_data.push((k_history, AccountProperties::hash(props)));
        }
        if history == History::ContractSlotAlreadySet {
            pre_data.push((slot_key, parent_hash));
        }
        let leaf_count_before = 2 + pre_data.len() as u64;
        let (root, leaves, siblings) = build_dense_tree(&pre_data);
        let proof_for = |idx: usize| -> StorageProof {
            let (i, leaf) = &leaves[idx];
            StorageProof::Existing(SlotProofEntry {
                index: *i,
                value: leaf.value,
                next_index: leaf.next_index,
                siblings: siblings[idx].clone(),
            })
        };

        let sender_after = encode_account_props(1, sender_balance_before - fee);
        let coinbase_after = encode_account_props(0, coinbase_balance_before + fee);

        let mut operations = vec![WriteOp::Update { index: 2 }, WriteOp::Update { index: 3 }];
        let mut entries = vec![
            (k_sender, AccountProperties::hash(&sender_after)),
            (k_coinbase, AccountProperties::hash(&coinbase_after)),
        ];
        if history == History::Contract {
            let prev_index = leaves
                .iter()
                .filter(|(_, l)| l.key < slot_key)
                .max_by_key(|(_, l)| l.key)
                .unwrap()
                .0;
            operations.push(WriteOp::Insert { prev_index });
            entries.push((slot_key, parent_hash));
        }
        let tree_update = BatchTreeUpdate {
            operations,
            entries,
            sorted_leaves: leaves.clone(),
            intermediate_hashes: vec![],
            leaf_count_before,
        };
        let interop_proofs = Some(interop_proofs_nonsettlement(&tree_update));

        // The block's storage proofs: the two executed accounts, plus whatever
        // the EIP-2935 step reads.
        // Leaf index 0 is the MIN guard and 1 the MAX guard, so the pre-state
        // data leaves start at 2 in the order `pre_data` lists them.
        let mut storage_proofs = vec![(k_sender, proof_for(2)), (k_coinbase, proof_for(3))];
        match history {
            History::Unproven => {}
            History::Absent => {
                storage_proofs.push((
                    k_history,
                    non_existence_proof(&leaves, &siblings, &k_history),
                ));
            }
            History::NoCode | History::Delegated => {
                storage_proofs.push((k_history, proof_for(4)));
            }
            History::Contract => {
                storage_proofs.push((k_history, proof_for(4)));
                storage_proofs
                    .push((slot_key, non_existence_proof(&leaves, &siblings, &slot_key)));
            }
            History::ContractSlotAlreadySet => {
                storage_proofs.push((k_history, proof_for(4)));
                storage_proofs.push((slot_key, proof_for(5)));
            }
        }

        let mut account_preimages = vec![
            (sender, sender_props.clone()),
            (coinbase, coinbase_props.clone()),
        ];
        if let Some(props) = history_props {
            account_preimages.push((history_addr, props));
        }

        // The pre-state ring holds the parent of block 6 at its owner-parent
        // slot; every other slot is empty.
        let mut ring = [B256::ZERO; 256];
        ring[255] = parent_hash;
        let mut ring_hasher = Blake2s256::new();
        for hash in &ring[..255] {
            ring_hasher.update(hash.as_slice());
        }
        ring_hasher.update(ring[255].as_slice());
        let block_hashes_blake_before = B256::from_slice(&ring_hasher.finalize());

        // The sealed header hash, derived from the two AtlasV4 Merkle roots. A
        // guest that kept the keccak rolling hash produces a different value.
        let tx_hash = crate::hash::keccak256(&signed_bytes);
        let receipt = crate::block_roots::receipt_leaf(0, true, GAS_USED, &[]);
        let block_header_hash = crate::block_header::compute_block_header_hash(
            &parent_hash,
            &coinbase.into_array(),
            &crate::block_roots::block_tx_tree_root(&[tx_hash]),
            &crate::block_roots::block_tx_tree_root(&[receipt]),
            BLOCK_NUMBER,
            block_gas_limit,
            GAS_USED,
            TIMESTAMP,
            &B256::from([1u8; 32]),
            BASE_FEE,
        );

        BatchInput {
            version: crate::types::BATCH_INPUT_VERSION,
            chain_id: 1,
            spec_id: 3,
            protocol_version_minor: 32,
            batch_meta: BatchMeta {
                tree_root_before: root,
                leaf_count_before,
                block_number_before: BLOCK_NUMBER - 1,
                last_block_timestamp_before: 0,
                block_hashes_blake_before,
                previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO,
                da_commitment_scheme: 2,
                pubdata: vec![],
                multichain_root: B256::ZERO,
                sl_chain_id: 0,
                blob_versioned_hashes: vec![],
                tree_update: Some(tree_update),
                account_preimages_after: vec![
                    (sender, sender_after),
                    (coinbase, coinbase_after),
                ],
                fri_proof_verification_enabled: false,
                max_tx_gas_limit,
                interop_proofs,
            },
            blocks: vec![BlockInput {
                number: BLOCK_NUMBER,
                timestamp: TIMESTAMP,
                base_fee: BASE_FEE,
                gas_limit: block_gas_limit,
                coinbase,
                prev_randao: B256::from([1u8; 32]),
                block_header_hash,
                storage_proofs,
                account_preimages,
                transactions: vec![TxInput {
                    chain_id: Some(1),
                    gas_used_override: Some(GAS_USED),
                    force_fail: false,
                    auth: TxAuth::L2 { signed_bytes },
                }],
                block_hashes: vec![(BLOCK_NUMBER - 1, parent_hash)],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            }],
            bytecodes: vec![],
        }
    }

    /// An AtlasV4 block commits the two depth-32 Blake2s Merkle roots. The
    /// fixture's sealed header hash is built from those roots, so the executor's
    /// own header check pins the choice; this test additionally shows the
    /// AtlasV3 rolling-hash header is a different value, so the check is not
    /// passing by accident.
    #[test]
    fn atlas_v4_block_commits_the_merkle_roots() {
        let batch = atlas_v4_transfer_batch(History::Contract);
        let (output, commitment) = executor::execute_and_commit(&batch);
        assert_ne!(commitment, B256::ZERO);

        let block = &batch.blocks[0];
        let computed = output.block_results[0].computed_block_header_hash;
        assert_eq!(computed, block.block_header_hash);

        let tx_hash = output.block_results[0].tx_results.len();
        assert_eq!(tx_hash, 1, "the fixture runs exactly one transaction");

        let rolling = crate::block_header::compute_block_header_hash(
            &atlas_v4_parent_hash(),
            &block.coinbase.into_array(),
            &crate::block_header::transactions_rolling_hash(
                &[crate::hash::keccak256(match &block.transactions[0].auth {
                    TxAuth::L2 { signed_bytes } => signed_bytes,
                    _ => unreachable!("the fixture carries one L2 transaction"),
                })],
                crate::block_header::KECCAK_EMPTY,
            ),
            &B256::ZERO,
            block.number,
            block.gas_limit,
            21_000,
            block.timestamp,
            &block.prev_randao,
            block.base_fee,
        );
        assert_ne!(
            computed, rolling,
            "an AtlasV4 header must not carry the keccak rolling hash and a zero \
             receipts root"
        );
    }

    /// The EIP-2935 write puts the block's parent hash into ring slot
    /// `(number - 1) % 8191`, and it enters the batch write set. Dropping the
    /// leaf from the tree update makes the batch unprovable, which shows the
    /// write really reaches `tree_root_after`.
    #[test]
    fn atlas_v4_writes_the_parent_hash_into_the_history_slot() {
        let batch = atlas_v4_transfer_batch(History::Contract);
        let update = batch.batch_meta.tree_update.as_ref().unwrap();
        let slot_key = derive_flat_storage_key(
            &history_address().into_array(),
            &B256::from(U256::from(5u64).to_be_bytes::<32>()),
        );
        assert!(
            update.entries.contains(&(slot_key, atlas_v4_parent_hash())),
            "the fixture's tree update must carry the ring-slot write"
        );
        let (_output, commitment) = executor::execute_and_commit(&batch);
        assert_ne!(commitment, B256::ZERO);

        let mut without_write = batch.clone();
        let update = without_write.batch_meta.tree_update.as_mut().unwrap();
        update.operations.pop();
        update.entries.pop();
        assert!(
            std::panic::catch_unwind(|| executor::execute_and_commit(&without_write)).is_err(),
            "a tree update missing the EIP-2935 write must be rejected"
        );
    }

    /// Native returns without writing when the history account is not a
    /// contract: an absent account, an account with no code, and an EIP-7702
    /// delegation designator all skip the write.
    #[test]
    fn atlas_v4_skips_the_history_write_when_the_account_is_not_a_contract() {
        for history in [History::Absent, History::NoCode, History::Delegated] {
            let batch = atlas_v4_transfer_batch(history);
            let update = batch.batch_meta.tree_update.as_ref().unwrap();
            assert_eq!(
                update.entries.len(),
                2,
                "only the two executed accounts change"
            );
            let (_output, commitment) = executor::execute_and_commit(&batch);
            assert_ne!(commitment, B256::ZERO);
        }
    }

    /// The write joins the batch write set only when it changes the slot. A ring
    /// slot that already holds this block's parent hash contributes nothing.
    #[test]
    fn atlas_v4_skips_the_history_write_when_the_slot_already_holds_the_value() {
        let batch = atlas_v4_transfer_batch(History::ContractSlotAlreadySet);
        assert_eq!(batch.batch_meta.tree_update.as_ref().unwrap().entries.len(), 2);
        let (_output, commitment) = executor::execute_and_commit(&batch);
        assert_ne!(commitment, B256::ZERO);
    }

    /// The `is_contract()` gate decides whether the batch writes a state change,
    /// so it must rest on an authenticated pre-state. A witness that omits the
    /// history contract's proof is rejected with a named error.
    #[test]
    #[should_panic(expected = "carries no authenticated pre-state for the")]
    fn atlas_v4_requires_the_history_contract_pre_state() {
        executor::execute_and_commit(&atlas_v4_transfer_batch(History::Unproven));
    }

    /// The ring slot's own pre-state must be authenticated too: the write joins
    /// the write set only when it differs from that value.
    #[test]
    #[should_panic(expected = "carries no authenticated pre-state for the")]
    fn atlas_v4_requires_the_history_slot_pre_state() {
        let mut batch = atlas_v4_transfer_batch(History::Contract);
        let slot_key = derive_flat_storage_key(
            &history_address().into_array(),
            &B256::from(U256::from(5u64).to_be_bytes::<32>()),
        );
        batch.blocks[0].storage_proofs.retain(|(k, _)| *k != slot_key);
        executor::execute_and_commit(&batch);
    }

    /// The sealed header hash is mandatory at AtlasV4: it is the only check that
    /// ties the Merkle tree leaves to the block native sealed.
    #[test]
    #[should_panic(expected = "must carry the sealed block_header_hash")]
    fn atlas_v4_requires_a_sealed_block_header_hash() {
        let mut batch = atlas_v4_transfer_batch(History::Contract);
        batch.blocks[0].block_header_hash = B256::ZERO;
        executor::execute_and_commit(&batch);
    }

    /// A chain may raise its EIP-7825 per-transaction cap above Ethereum's
    /// 2^24, and native then accepts a transaction above that value. REVM's
    /// Osaka default caps every transaction at 2^24, so the executor must
    /// override it and leave native's rule to the transaction builder.
    #[test]
    fn atlas_v4_accepts_a_transaction_above_the_ethereum_gas_cap() {
        const OVER_ETHEREUM_CAP: u64 = (1 << 24) + 1;
        let batch = atlas_v4_transfer_batch_with_limits(
            History::Contract,
            1 << 25,
            OVER_ETHEREUM_CAP,
            1 << 25,
        );
        let (output, commitment) = executor::execute_and_commit(&batch);
        assert_ne!(commitment, B256::ZERO);
        assert!(
            output.block_results[0].tx_results[0].success,
            "native accepts this transaction, so the guest must execute it"
        );
    }

    /// Native's transaction dispatch compiles no type-3 arm in any shipped
    /// build, so an AtlasV4 batch carrying a blob transaction is rejected.
    #[test]
    #[should_panic(expected = "blob transactions are not enabled at AtlasV4")]
    fn atlas_v4_rejects_blob_transactions() {
        use alloy_consensus::{SignableTransaction, TxEip4844, TxEip4844Variant, TxEnvelope};
        use alloy_eips::eip2718::Encodable2718;
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let tx = TxEip4844 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 0,
            to: Address::ZERO,
            value: U256::ZERO,
            access_list: Default::default(),
            blob_versioned_hashes: vec![B256::repeat_byte(0x01)],
            max_fee_per_blob_gas: 1,
            input: Default::default(),
        };
        let sighash = tx.signature_hash();
        let (sig, recid) = sk.sign_prehash_recoverable(sighash.as_slice()).unwrap();
        let sig_bytes = sig.to_bytes();
        let signature = alloy_primitives::Signature::new(
            U256::from_be_slice(&sig_bytes[..32]),
            U256::from_be_slice(&sig_bytes[32..]),
            recid.is_y_odd(),
        );
        let envelope =
            TxEnvelope::Eip4844(TxEip4844Variant::TxEip4844(tx).into_signed(signature));
        let mut signed = Vec::new();
        envelope.encode_2718(&mut signed);

        let mut batch = atlas_v4_transfer_batch(History::Contract);
        batch.blocks[0].transactions.push(TxInput {
            chain_id: Some(1),
            gas_used_override: Some(0),
            force_fail: true,
            auth: TxAuth::L2 { signed_bytes: signed },
        });
        executor::execute_and_commit(&batch);
    }
}
