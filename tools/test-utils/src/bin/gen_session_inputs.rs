//! Generate the four framed guest inputs for a fixture session
//! (.github/workflows/fixture-session.yaml) without a server: each input is
//! a minimal proven AtlasV4 batch rebuilt through lib's public API because
//! lib/ is byte-frozen. The four batches differ only in the L1 transaction's
//! `value` word, which changes the tx hash and therefore the batch commitment.
//! The forced-fail deposit exercises the priority-operation commitment without
//! adding execution writes, keeping the authenticated state fixture minimal.
//!
//! These are wire-v5 protocol-v32 AtlasV4 inputs. They include the v5 chain
//! config, authenticated interop-boundary reads, the authenticated EIP-2935
//! no-contract case and a sealed AtlasV4 block header. Every encoded batch is
//! decoded and executed through the version-dispatching bincode entry point
//! before it is written, so a schema or execution regression fails here
//! instead of after a GPU prove.
//!
//! Usage: gen_session_inputs <output-dir>
//!        # writes batch-{1..4}.bin and input-manifest.json

use alloy_primitives::{Address, B256, U256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zksync_os_zisk_lib::block_header::compute_block_header_hash;
use zksync_os_zisk_lib::block_roots::{block_tx_tree_root, receipt_leaf};
use zksync_os_zisk_lib::commitment::block_hashes_blake;
use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::merkle::{
    blake2s, derive_account_properties_key, derive_flat_storage_key, empty_subtree_hash, hash_leaf,
    AccountProperties, NeighborProofEntry, SlotProofEntry, StorageProof, TreeLeaf, TREE_DEPTH,
};
use zksync_os_zisk_lib::types::{
    BatchInput, BatchMeta, BlockInput, InteropCommitmentTreeProofs, InteropSlotProofs,
    L2ToL1LogEntry, TxAuth, TxInput, BATCH_INPUT_VERSION, PUBDATA_CONTENT_FULL,
};
use zksync_os_zisk_lib::wire;

const FIXTURE_SPEC_ID: u8 = 3;
const FIXTURE_PROTOCOL_VERSION_MINOR: u32 = 32;
const FIXTURE_BLOCK_NUMBER: u64 = 6;
const FIXTURE_TIMESTAMP: u64 = 1_700_000_000;
const FIXTURE_BASE_FEE: u64 = 250_000_000;
const FIXTURE_BLOCK_GAS_LIMIT: u64 = 80_000_000;
const FIXTURE_MAX_TX_GAS_LIMIT: u64 = 1 << 24;

// This account-state nonce is public, deterministic test-vector data, not a
// nonce used by a cryptographic primitive.
const FIXTURE_ACCOUNT_NONCE: u64 = 0;

#[derive(Serialize)]
struct InputManifest {
    schema_version: u32,
    batches: Vec<InputRecord>,
}

#[derive(Serialize)]
struct InputRecord {
    input_filename: String,
    wire_version: u32,
    spec_id: u8,
    protocol_version_minor: u32,
    framed_input_sha256: String,
    native_commitment: String,
}

fn compress(lhs: &B256, rhs: &B256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(lhs.as_slice());
    buf[32..].copy_from_slice(rhs.as_slice());
    blake2s(&buf)
}

/// Dense Merkle tree over MIN/MAX guards plus the supplied data leaves. The
/// returned leaves keep their dense indices, while their linked-list pointers
/// follow key order.
fn build_dense_tree(data: &[(B256, B256)]) -> (B256, Vec<(u64, TreeLeaf)>, Vec<Vec<B256>>) {
    let mut records = vec![
        (0, B256::ZERO, B256::ZERO),
        (1, B256::repeat_byte(0xff), B256::ZERO),
    ];
    records.extend(
        data.iter()
            .enumerate()
            .map(|(index, (key, value))| (2 + index as u64, *key, *value)),
    );

    let mut order: Vec<usize> = (0..records.len()).collect();
    order.sort_by_key(|&index| records[index].1);
    let mut next_indices = vec![0; records.len()];
    for adjacent in order.windows(2) {
        next_indices[adjacent[0]] = records[adjacent[1]].0;
    }
    next_indices[*order.last().expect("tree contains guard leaves")] = 1;

    let leaves: Vec<(u64, TreeLeaf)> = records
        .iter()
        .zip(&next_indices)
        .map(|((index, key, value), next_index)| {
            (
                *index,
                TreeLeaf {
                    key: *key,
                    value: *value,
                    next_index: *next_index,
                },
            )
        })
        .collect();

    let mut levels = vec![leaves
        .iter()
        .map(|(_, leaf)| hash_leaf(&leaf.key, &leaf.value, leaf.next_index))
        .collect::<Vec<_>>()];
    while levels.last().expect("leaf level exists").len() > 1 {
        let depth = levels.len() - 1;
        let current = levels.last().expect("current tree level exists");
        let next = (0..current.len().div_ceil(2))
            .map(|index| {
                let left = current[2 * index];
                let right = current
                    .get(2 * index + 1)
                    .copied()
                    .unwrap_or_else(|| empty_subtree_hash(depth as u8));
                compress(&left, &right)
            })
            .collect();
        levels.push(next);
    }

    let mut root = levels.last().expect("root level exists")[0];
    for depth in (levels.len() - 1)..TREE_DEPTH as usize {
        root = compress(&root, &empty_subtree_hash(depth as u8));
    }

    let siblings = (0..leaves.len() as u64)
        .map(|leaf_index| {
            (0..TREE_DEPTH as usize)
                .map(|depth| {
                    let sibling_index = ((leaf_index >> depth) ^ 1) as usize;
                    levels
                        .get(depth)
                        .and_then(|level| level.get(sibling_index))
                        .copied()
                        .unwrap_or_else(|| empty_subtree_hash(depth as u8))
                })
                .collect()
        })
        .collect();
    (root, leaves, siblings)
}

fn non_existence_proof(
    leaves: &[(u64, TreeLeaf)],
    siblings: &[Vec<B256>],
    key: &B256,
) -> StorageProof {
    let (left_index, left) = leaves
        .iter()
        .filter(|(_, leaf)| leaf.key < *key)
        .max_by_key(|(_, leaf)| leaf.key)
        .expect("MIN guard brackets every fixture key");
    let (right_index, right) = leaves
        .iter()
        .find(|(index, _)| *index == left.next_index)
        .expect("linked-list successor exists");
    let entry = |index: u64, leaf: &TreeLeaf| SlotProofEntry {
        index,
        value: leaf.value,
        next_index: leaf.next_index,
        siblings: siblings[index as usize].clone(),
    };
    StorageProof::NonExisting {
        left_neighbor: NeighborProofEntry {
            entry: entry(*left_index, left),
            leaf_key: left.key,
        },
        right_neighbor: NeighborProofEntry {
            entry: entry(*right_index, right),
            leaf_key: right.key,
        },
    }
}

fn interop_slot_keys() -> (B256, B256, B256) {
    const SYSTEM_CONTEXT: [u8; 20] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x0b,
    ];
    const MESSAGE_ROOT: [u8; 20] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x05,
    ];
    let settlement_layer_chain_id = derive_flat_storage_key(&SYSTEM_CONTEXT, &B256::ZERO);
    let height = derive_flat_storage_key(&MESSAGE_ROOT, &B256::with_last_byte(0x04));
    let nodes_base = alloy_primitives::keccak256(B256::with_last_byte(0x06));
    let root_slot = alloy_primitives::keccak256(nodes_base);
    (
        settlement_layer_chain_id,
        height,
        derive_flat_storage_key(&MESSAGE_ROOT, &root_slot),
    )
}

fn commitment_tree_slot_keys() -> (B256, B256) {
    const COMMITMENT_TREE: [u8; 20] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x12,
    ];
    let height = derive_flat_storage_key(&COMMITMENT_TREE, &B256::ZERO);
    let nodes_base = alloy_primitives::keccak256(B256::with_last_byte(0x02));
    let root_slot = alloy_primitives::keccak256(nodes_base);
    (
        height,
        derive_flat_storage_key(&COMMITMENT_TREE, &root_slot),
    )
}

fn interop_proofs_nonsettlement(
    leaves: &[(u64, TreeLeaf)],
    siblings: &[Vec<B256>],
) -> InteropSlotProofs {
    let (settlement_layer_chain_id, multichain_height, multichain_root) = interop_slot_keys();
    let (commitment_tree_height, commitment_tree_root) = commitment_tree_slot_keys();

    InteropSlotProofs {
        sl_chain_id: non_existence_proof(leaves, siblings, &settlement_layer_chain_id),
        multichain_height: non_existence_proof(leaves, siblings, &multichain_height),
        multichain_root: non_existence_proof(leaves, siblings, &multichain_root),
        commitment_tree: Some(InteropCommitmentTreeProofs {
            height_begin: non_existence_proof(leaves, siblings, &commitment_tree_height),
            root_begin: non_existence_proof(leaves, siblings, &commitment_tree_root),
            height_end: non_existence_proof(leaves, siblings, &commitment_tree_height),
            root_end: non_existence_proof(leaves, siblings, &commitment_tree_root),
        }),
    }
}

fn encode_account_props(fixture_account_nonce: u64, balance: U256) -> Vec<u8> {
    let mut data = vec![0u8; 124];
    data[8..16].copy_from_slice(&fixture_account_nonce.to_be_bytes());
    data[16..48].copy_from_slice(&balance.to_be_bytes::<32>());
    data
}

/// ABI-encoded L2CanonicalTransaction with the given `value` (word 9).
fn l1_abi(sender: Address, recipient: Address, value: U256) -> Vec<u8> {
    let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
    abi[31] = 0x20; // outer offset
    abi[32 + 31] = 0x7f; // txType
    abi[32 + 32 + 12..32 + 32 + 32].copy_from_slice(sender.as_slice()); // from
    abi[32 + 64 + 12..32 + 64 + 32].copy_from_slice(recipient.as_slice()); // to
    abi[32 + 96 + 24..32 + 96 + 32].copy_from_slice(&21_000u64.to_be_bytes()); // gasLimit
    abi[32 + 160 + 16..32 + 160 + 32].copy_from_slice(&250_000_000u128.to_be_bytes()); // maxFeePerGas
    abi[32 + 288..32 + 288 + 32].copy_from_slice(&value.to_be_bytes::<32>()); // value
    abi[32 + 352 + 12..32 + 352 + 32].copy_from_slice(sender.as_slice()); // reserved[1]=refund
    let dyn_base = 19u32 * 32;
    for j in 0..5u32 {
        let off = 32 + (14 + j as usize) * 32;
        abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
    }
    abi
}

fn build_batch_input(value: U256) -> BatchInput {
    let sender: Address = "0x1000000000000000000000000000000000000001"
        .parse()
        .unwrap();
    let recipient: Address = "0x2000000000000000000000000000000000000002"
        .parse()
        .unwrap();

    let balance_before = U256::from(10_000_000_000_000_000_000u128);
    let sender_props = encode_account_props(FIXTURE_ACCOUNT_NONCE, balance_before);
    let sender_props_hash = AccountProperties::hash(&sender_props);
    let sender_flat_key = derive_account_properties_key(&sender.into_array());

    let (tree_root, leaves, siblings) = build_dense_tree(&[(sender_flat_key, sender_props_hash)]);
    let leaf_count = leaves.len() as u64;
    let proof = StorageProof::Existing(SlotProofEntry {
        index: 2,
        value: sender_props_hash,
        next_index: leaves[2].1.next_index,
        siblings: siblings[2].clone(),
    });

    // The forced-fail path has no state writes, so the same authenticated tree
    // supplies the before/after interop-boundary proofs.
    let interop_proofs = Some(interop_proofs_nonsettlement(&leaves, &siblings));

    let abi = l1_abi(sender, recipient, value);
    let l1_tx_hash = alloy_primitives::keccak256(&abi);
    let parent_hash = B256::repeat_byte(0x77);
    let history_address: Address = "0x0000f90827f1c53a10cb7a02335b175320002935"
        .parse()
        .expect("fixture history address is valid");
    let history_key = derive_account_properties_key(&history_address.into_array());
    let block_header_hash = compute_block_header_hash(
        &parent_hash,
        &sender.into_array(),
        &block_tx_tree_root(&[l1_tx_hash]),
        &block_tx_tree_root(&[receipt_leaf(0x7f, false, 21_000, &[])]),
        FIXTURE_BLOCK_NUMBER,
        FIXTURE_BLOCK_GAS_LIMIT,
        21_000,
        FIXTURE_TIMESTAMP,
        &B256::from([1u8; 32]),
        FIXTURE_BASE_FEE,
    );

    BatchInput {
        version: BATCH_INPUT_VERSION,
        chain_id: 270,
        spec_id: FIXTURE_SPEC_ID,
        protocol_version_minor: FIXTURE_PROTOCOL_VERSION_MINOR,
        batch_meta: BatchMeta {
            tree_root_before: tree_root,
            leaf_count_before: leaf_count,
            block_number_before: FIXTURE_BLOCK_NUMBER - 1,
            last_block_timestamp_before: 0,
            block_hashes_blake_before: block_hashes_blake(&[B256::ZERO; 255], &parent_hash),
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
            max_tx_gas_limit: FIXTURE_MAX_TX_GAS_LIMIT,
            pubdata_content: PUBDATA_CONTENT_FULL,
            interop_proofs,
        },
        blocks: vec![BlockInput {
            number: FIXTURE_BLOCK_NUMBER,
            timestamp: FIXTURE_TIMESTAMP,
            base_fee: FIXTURE_BASE_FEE,
            gas_limit: FIXTURE_BLOCK_GAS_LIMIT,
            coinbase: sender, // coinbase = sender so no extra account proof is needed
            prev_randao: B256::from([1u8; 32]),
            block_header_hash,
            storage_proofs: vec![
                (sender_flat_key, proof),
                (
                    history_key,
                    non_existence_proof(&leaves, &siblings, &history_key),
                ),
            ],
            account_preimages: vec![(sender, sender_props)],
            transactions: vec![TxInput {
                chain_id: Some(270),
                // Zero preserves the minimal force-fail path; the handler's
                // intrinsic phase still reports 21,000 gas in the receipt.
                gas_used_override: Some(0),
                force_fail: true,
                auth: TxAuth::L1 {
                    tx_hash: l1_tx_hash,
                    abi_encoded: abi,
                },
            }],
            block_hashes: vec![(FIXTURE_BLOCK_NUMBER - 1, parent_hash)],
            l2_to_l1_logs: vec![L2ToL1LogEntry {
                l2_shard_id: 0,
                is_service: true,
                tx_number_in_block: 0,
                sender: "0x0000000000000000000000000000000000008001"
                    .parse()
                    .unwrap(),
                key: l1_tx_hash,
                value: B256::ZERO, // force_fail → success=false → value=0
            }],
            expected_tree_root: B256::ZERO,
        }],
        bytecodes: vec![],
    }
}

/// ZiSK stdin framing (prover/src/prover.rs write_zisk_input):
/// [len u64 LE][wire bytes][zero pad to an 8-byte boundary].
fn frame(wire_bytes: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + wire_bytes.len() + 8);
    buf.extend_from_slice(&(wire_bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(wire_bytes);
    let padding = (8 - ((8 + wire_bytes.len()) % 8)) % 8;
    buf.extend(std::iter::repeat_n(0u8, padding));
    buf
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn main() -> anyhow::Result<()> {
    let out_dir = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: gen_session_inputs <output-dir>"))?;
    let out_dir = std::path::Path::new(&out_dir);
    std::fs::create_dir_all(out_dir)?;

    let one_eth = U256::from(10u64).pow(U256::from(18));
    let mut commitments = Vec::new();
    let mut records = Vec::new();
    for n in 1u64..=4 {
        let input = build_batch_input(one_eth * U256::from(n));
        let wire_bytes = wire::encode(&input)?;
        anyhow::ensure!(
            wire::batch_input_version(&wire_bytes)? == BATCH_INPUT_VERSION,
            "batch {n}: encoded an unexpected wire version"
        );
        let decoded: BatchInput = wire::decode(&wire_bytes)?;
        anyhow::ensure!(
            wire::encode(&decoded)? == wire_bytes,
            "batch {n}: wire-v5 round trip changed the bytes"
        );
        let (_output, commitment) =
            executor::execute_and_commit_from_bincode(&wire_bytes).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(commitment != B256::ZERO, "batch {n}: zero commitment");
        anyhow::ensure!(
            !commitments.contains(&commitment),
            "batch {n}: commitment collides with an earlier batch"
        );
        commitments.push(commitment);

        let filename = format!("batch-{n}.bin");
        let framed = frame(&wire_bytes);
        std::fs::write(out_dir.join(&filename), &framed)?;
        let framed_input_sha256 = sha256_hex(&framed);
        println!(
            "{filename}: wire v{} spec {} minor {}; framed sha256 {}; native commitment {commitment}",
            BATCH_INPUT_VERSION,
            FIXTURE_SPEC_ID,
            FIXTURE_PROTOCOL_VERSION_MINOR,
            framed_input_sha256
        );
        records.push(InputRecord {
            input_filename: filename,
            wire_version: BATCH_INPUT_VERSION,
            spec_id: FIXTURE_SPEC_ID,
            protocol_version_minor: FIXTURE_PROTOCOL_VERSION_MINOR,
            framed_input_sha256,
            native_commitment: commitment.to_string(),
        });
    }
    let mut manifest = serde_json::to_vec_pretty(&InputManifest {
        schema_version: 1,
        batches: records,
    })?;
    manifest.push(b'\n');
    std::fs::write(out_dir.join("input-manifest.json"), manifest)?;
    println!(
        "wrote 4 framed wire-v5 inputs and input-manifest.json to {}",
        out_dir.display()
    );
    Ok(())
}
