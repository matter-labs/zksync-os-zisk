//! Generate the four framed guest inputs for a fixture session
//! (.github/workflows/fixture-session.yaml) without a server: each input is
//! the minimal proven batch from `lib/src/test_proven.rs`
//! (`export_proven_input_for_emulator`), rebuilt here through lib's public
//! API because lib/ is byte-frozen. The four batches differ only in the L1
//! transaction's `value` word, which changes the tx hash and therefore the
//! batch commitment. The forced-fail deposit refunds `value` to the sender,
//! so each input carries the matching after-preimage and a one-write
//! `BatchTreeUpdate` over the minimal tree.
//!
//! These are intentionally frozen wire-v3 AtlasV2 inputs. Every encoded batch
//! is decoded and executed through the version-dispatching bincode entry point
//! before it is written, so a schema or execution regression fails here
//! instead of after a GPU prove.
//!
//! Usage: gen_session_inputs <output-dir>
//!        # writes batch-{1..4}.bin and input-manifest.json

use alloy_primitives::{Address, B256, U256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zksync_os_zisk_lib::commitment::block_hashes_blake;
use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::merkle::{
    blake2s, derive_account_properties_key, empty_subtree_hash, hash_leaf, AccountProperties,
    TREE_DEPTH,
};
use zksync_os_zisk_lib::wire::{
    self,
    v3::{
        BatchInput, BatchMeta, BatchTreeUpdate, BlockInput, L2ToL1LogEntry, SlotProofEntry,
        StorageProof, TreeLeaf, TxAuth, TxInput, WriteOp,
    },
};

const FIXTURE_SPEC_ID: u8 = 1;
const FIXTURE_PROTOCOL_VERSION_MINOR: u32 = 30;

// This account-state nonce is public, deterministic test-vector data, not a
// nonce used by a cryptographic primitive.
const FIXTURE_ACCOUNT_NONCE: u64 = 0;

const HISTORICAL_BATCH_1: &str =
    include_str!("../../../../lib/testdata/wire-v3-session-batch-1.hex");

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

/// Minimal merkle tree: MIN_GUARD (idx 0), MAX_GUARD (idx 1), one data leaf
/// (idx 2). Returns (root, leaf_count, siblings for leaf 2).
fn build_minimal_tree(data_key: &B256, data_value: &B256) -> (B256, u64, Vec<B256>) {
    let leaf0 = hash_leaf(&B256::ZERO, &B256::ZERO, 2);
    let leaf1 = hash_leaf(&B256::repeat_byte(0xff), &B256::ZERO, 1);
    let leaf2 = hash_leaf(data_key, data_value, 1);

    let node_01 = compress(&leaf0, &leaf1);
    let node_23 = compress(&leaf2, &empty_subtree_hash(0));
    let mut current = compress(&node_01, &node_23);
    for d in 2..TREE_DEPTH {
        current = compress(&current, &empty_subtree_hash(d));
    }

    let mut siblings = vec![empty_subtree_hash(0), node_01];
    for d in 2..TREE_DEPTH {
        siblings.push(empty_subtree_hash(d));
    }
    (current, 3, siblings)
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

    let (tree_root, leaf_count, siblings) =
        build_minimal_tree(&sender_flat_key, &sender_props_hash);
    let proof = StorageProof::Existing(SlotProofEntry {
        index: 2,
        value: sender_props_hash,
        next_index: 1,
        siblings,
    });

    // The failed deposit refunds `value` to reserved[1] (= sender), so the
    // post-state carries the credited balance.
    let sender_props_after = encode_account_props(FIXTURE_ACCOUNT_NONCE, balance_before + value);
    let sender_props_after_hash = AccountProperties::hash(&sender_props_after);
    let tree_update = BatchTreeUpdate {
        operations: vec![WriteOp::Update { index: 2 }],
        entries: vec![(sender_flat_key, sender_props_after_hash)],
        // All three pre-state leaves: leaf 2 is written, the guards anchor
        // its level-1 sibling; everything beyond leaf_count is provably empty.
        sorted_leaves: vec![
            (
                0,
                TreeLeaf {
                    key: B256::ZERO,
                    value: B256::ZERO,
                    next_index: 2,
                },
            ),
            (
                1,
                TreeLeaf {
                    key: B256::repeat_byte(0xff),
                    value: B256::ZERO,
                    next_index: 1,
                },
            ),
            (
                2,
                TreeLeaf {
                    key: sender_flat_key,
                    value: sender_props_hash,
                    next_index: 1,
                },
            ),
        ],
        intermediate_hashes: vec![],
        leaf_count_before: leaf_count,
    };

    let abi = l1_abi(sender, recipient, value);
    let l1_tx_hash = alloy_primitives::keccak256(&abi);

    BatchInput {
        version: wire::v3::BATCH_INPUT_VERSION,
        chain_id: 270,
        spec_id: FIXTURE_SPEC_ID,
        protocol_version_minor: FIXTURE_PROTOCOL_VERSION_MINOR,
        batch_meta: BatchMeta {
            tree_root_before: tree_root,
            leaf_count_before: leaf_count,
            block_number_before: 0,
            last_block_timestamp_before: 0,
            block_hashes_blake_before: block_hashes_blake(&[B256::ZERO; 255], &B256::ZERO),
            previous_block_hashes: vec![],
            upgrade_tx_hash: B256::ZERO,
            da_commitment_scheme: 2,
            pubdata: vec![],
            multichain_root: B256::ZERO,
            sl_chain_id: 0,
            blob_versioned_hashes: vec![],
            tree_update: Some(tree_update),
            account_preimages_after: vec![(sender, sender_props_after)],
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
                auth: TxAuth::L1 {
                    tx_hash: l1_tx_hash,
                    abi_encoded: abi,
                },
            }],
            block_hashes: vec![],
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

fn decode_hex_fixture(source: &str) -> anyhow::Result<Vec<u8>> {
    let digits: Vec<u8> = source
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let (pairs, remainder) = digits.as_slice().as_chunks::<2>();
    anyhow::ensure!(
        remainder.is_empty(),
        "historical fixture has odd hex length"
    );
    pairs
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
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
            wire::batch_input_version(&wire_bytes)? == wire::v3::BATCH_INPUT_VERSION,
            "batch {n}: encoded an unexpected wire version"
        );
        let decoded: wire::v3::BatchInput = wire::decode(&wire_bytes)?;
        anyhow::ensure!(
            wire::encode(&decoded)? == wire_bytes,
            "batch {n}: frozen wire-v3 round trip changed the bytes"
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
        if n == 1 {
            anyhow::ensure!(
                framed == decode_hex_fixture(HISTORICAL_BATCH_1)?,
                "batch 1 differs from lib/testdata/wire-v3-session-batch-1.hex"
            );
        }
        std::fs::write(out_dir.join(&filename), &framed)?;
        let framed_input_sha256 = sha256_hex(&framed);
        println!(
            "{filename}: wire v{} spec {} minor {}; framed sha256 {}; native commitment {commitment}",
            wire::v3::BATCH_INPUT_VERSION,
            FIXTURE_SPEC_ID,
            FIXTURE_PROTOCOL_VERSION_MINOR,
            framed_input_sha256
        );
        records.push(InputRecord {
            input_filename: filename,
            wire_version: wire::v3::BATCH_INPUT_VERSION,
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
        "wrote 4 framed wire-v3 inputs and input-manifest.json to {}",
        out_dir.display()
    );
    Ok(())
}
