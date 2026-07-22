//! Transaction authentication and construction.
//!
//! All execution-critical fields are derived from cryptographically
//! authenticated data: RLP-encoded signed bytes for L2, ABI encoding
//! for L1/Upgrade. Only ZiSK-specific hints (gas_used_override, force_fail)
//! come from the untrusted TxInput.

use revm::context::TxEnv;
use revm::primitives::{B256, Bytes, U256};
use zksync_os_revm::transaction::abstraction::ZKsyncTxBuilder;
use zksync_os_revm::ZKsyncTx;

use crate::types::*;

// L2CanonicalTransaction ABI layout (after the 32-byte outer offset word).
// See zksync-era/contracts/l1-contracts/contracts/common/Messaging.sol
mod abi_layout {
    pub const OUTER_OFFSET: usize = 32;
    pub const TX_TYPE: usize = 0;
    pub const FROM: usize = 1;
    pub const TO: usize = 2;
    pub const GAS_LIMIT: usize = 3;
    pub const MAX_FEE_PER_GAS: usize = 5;
    pub const NONCE: usize = 8;
    pub const VALUE: usize = 9;
    pub const MINT: usize = 10;      // reserved[0]
    pub const REFUND: usize = 11;    // reserved[1]
    pub const DATA_OFFSET: usize = 14;

    pub fn word(abi: &[u8], field: usize) -> alloy_primitives::U256 {
        let off = OUTER_OFFSET + field * 32;
        alloy_primitives::U256::from_be_slice(&abi[off..off + 32])
    }

    pub fn addr(abi: &[u8], field: usize) -> alloy_primitives::Address {
        alloy_primitives::Address::from_slice(&word(abi, field).to_be_bytes::<32>()[12..])
    }

    /// Extract the dynamic `data` (calldata) field from the ABI encoding.
    pub fn data(abi: &[u8]) -> Vec<u8> {
        let rel_offset: usize = word(abi, DATA_OFFSET).to();
        let abs_offset = OUTER_OFFSET + rel_offset;
        let len: usize = alloy_primitives::U256::from_be_slice(
            &abi[abs_offset..abs_offset + 32],
        ).to();
        abi[abs_offset + 32..abs_offset + 32 + len].to_vec()
    }
}

/// Verify the transaction's authenticity, compute its hash, and build
/// the REVM transaction.
///
/// All execution fields are derived from the authenticated source:
/// - L1/Upgrade: from the ABI encoding (hash-verified against tx_hash)
/// - L2: from the RLP-encoded signed bytes (signature-verified via ecrecover)
/// - System: from the EIP-2718 encoding (hash-verified against tx_hash)
///
/// Only `gas_used_override` and `force_fail` are taken from TxInput.
/// `block_gas_limit` caps system transactions, whose own gas limit is zero.
///
/// Public so host-side witness builders (the dump-to-BatchInput reader) can
/// run their read-discovery pass through the exact same tx construction the
/// guest uses, instead of maintaining a drifting replica.
pub fn build_proven_tx(input: &TxInput, block_gas_limit: u64) -> (ZKsyncTx<TxEnv>, B256, u8) {
    match &input.auth {
        TxAuth::L1 { tx_hash, abi_encoded } | TxAuth::Upgrade { tx_hash, abi_encoded } => {
            build_l1_upgrade_tx(input, tx_hash, abi_encoded)
        }
        TxAuth::L2 { signed_bytes } => build_l2_tx(input, signed_bytes),
        TxAuth::System { tx_hash, encoded_2718 } => {
            build_system_tx(input, tx_hash, encoded_2718, block_gas_limit)
        }
    }
}

/// Build a transaction from ABI-encoded L2CanonicalTransaction data.
/// All execution fields are extracted from the ABI encoding, which is
/// hash-verified: keccak256(abi_encoded) == tx_hash.
fn build_l1_upgrade_tx(
    input: &TxInput,
    tx_hash: &B256,
    abi_encoded: &[u8],
) -> (ZKsyncTx<TxEnv>, B256, u8) {
    // Verify the ABI encoding hashes to the claimed tx_hash.
    let computed = crate::hash::keccak256(abi_encoded);
    assert_eq!(
        computed, *tx_hash,
        "tx hash mismatch: keccak256(abi)={computed}, claimed={tx_hash}"
    );

    // Extract all execution fields from the ABI encoding.
    let tx_type: u8 = abi_layout::word(abi_encoded, abi_layout::TX_TYPE).to();
    let caller = abi_layout::addr(abi_encoded, abi_layout::FROM);
    let to = abi_layout::addr(abi_encoded, abi_layout::TO);
    let value = abi_layout::word(abi_encoded, abi_layout::VALUE);
    let raw_gas_limit: u64 = abi_layout::word(abi_encoded, abi_layout::GAS_LIMIT).to();
    let gas_price = abi_layout::word(abi_encoded, abi_layout::MAX_FEE_PER_GAS);
    let nonce: u64 = abi_layout::word(abi_encoded, abi_layout::NONCE).to();
    let mint = abi_layout::word(abi_encoded, abi_layout::MINT);
    let refund_recipient = abi_layout::addr(abi_encoded, abi_layout::REFUND);
    let data = abi_layout::data(abi_encoded);

    // Upgrade txs get extra gas headroom (EVM gas >> native gas).
    let gas_limit = if tx_type == 0x7e {
        raw_gas_limit.saturating_mul(10)
    } else {
        raw_gas_limit
    };

    let revm_kind = revm::primitives::TxKind::Call(to);

    let builder = TxEnv::builder()
        .caller(caller)
        .gas_limit(gas_limit)
        .gas_price(gas_price.to::<u128>())
        .kind(revm_kind)
        .value(value)
        .data(Bytes::from(data))
        .nonce(nonce)
        .tx_type(Some(tx_type))
        .chain_id(input.chain_id)
        .blob_hashes(vec![]);

    // Always pass the recipient, zero address included: the Atlas handler
    // requires one for every L1->L2 tx, and native resolves zero itself.
    let tx = ZKsyncTxBuilder::new()
        .base(builder)
        .mint(mint)
        .refund_recipient(Some(refund_recipient))
        .gas_used_override(input.gas_used_override)
        .force_fail(input.force_fail)
        .tx_hash(*tx_hash)
        .build()
        .expect("failed to build ZKsyncTx");

    (tx, *tx_hash, tx_type)
}

/// Build a transaction from EIP-2718 RLP-encoded signed bytes.
/// All execution fields are decoded from the signed envelope. The signature
/// is verified via ecrecover to authenticate the caller.
fn build_l2_tx(input: &TxInput, signed_bytes: &[u8]) -> (ZKsyncTx<TxEnv>, B256, u8) {
    use alloy_consensus::transaction::SignerRecoverable;
    use alloy_consensus::TxEnvelope;
    use alloy_eips::Decodable2718;
    use alloy_consensus::Transaction;

    let envelope = TxEnvelope::decode_2718(&mut &signed_bytes[..])
        .expect("failed to decode EIP-2718 signed transaction");

    let caller = envelope
        .recover_signer()
        .expect("failed to recover signer from transaction signature");

    let tx_hash = crate::hash::keccak256(signed_bytes);

    // Extract all execution fields from the decoded envelope.
    let revm_kind = match envelope.to() {
        Some(addr) => revm::primitives::TxKind::Call(addr),
        None => revm::primitives::TxKind::Create,
    };
    let value = envelope.value();
    let data = envelope.input().clone();
    let nonce = envelope.nonce();
    let gas_limit = envelope.gas_limit();
    let gas_price = envelope.max_fee_per_gas();
    let gas_priority_fee = envelope.max_priority_fee_per_gas();
    let chain_id = envelope.chain_id().or(input.chain_id);
    let tx_type = envelope.tx_type() as u8;
    // Envelope-derived typed-tx payloads (all signature-authenticated):
    // EIP-2930+ access lists change warm/cold gas semantics, the EIP-7702
    // authorization list is mandatory for type-4 txs, blob fields for
    // type-3. Mirrors the server's consistency-checker conversion
    // (zk_tx_into_revm_tx), keeping both REVM consumers identical.
    let access_list = envelope.access_list().cloned().unwrap_or_default();
    let authorization_list = envelope
        .authorization_list()
        .map(|list| list.to_vec())
        .unwrap_or_default();
    let blob_hashes = envelope
        .blob_versioned_hashes()
        .map(|hashes| hashes.to_vec())
        .unwrap_or_default();
    let max_fee_per_blob_gas = envelope.max_fee_per_blob_gas().unwrap_or_default();

    let mut builder = TxEnv::builder()
        .caller(caller)
        .gas_limit(gas_limit)
        .gas_price(gas_price)
        .kind(revm_kind)
        .value(value)
        .data(data)
        .nonce(nonce)
        .access_list(access_list)
        .tx_type(Some(tx_type))
        .chain_id(chain_id)
        .blob_hashes(blob_hashes)
        .max_fee_per_blob_gas(max_fee_per_blob_gas)
        .authorization_list_signed(authorization_list);

    if let Some(fee) = gas_priority_fee {
        builder = builder.gas_priority_fee(Some(fee));
    }

    let tx = ZKsyncTxBuilder::new()
        .base(builder)
        .mint(U256::ZERO)
        .refund_recipient(None)
        .gas_used_override(input.gas_used_override)
        .force_fail(input.force_fail)
        .tx_hash(tx_hash)
        .build()
        .expect("failed to build ZKsyncTx");

    (tx, tx_hash, tx_type)
}

/// The system tx type byte (`SYSTEM_TX_TYPE_ID` in zksync-os-server types).
const SYSTEM_TX_TYPE: u8 = 0x7d;

/// The formal bootloader address — the protocol-defined sender of every
/// system transaction (a constant, never witness data).
const BOOTLOADER_FORMAL_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01,
];

/// Build a protocol-injected system transaction (interop root import,
/// SL-chain-id update, interop fee update) from its EIP-2718 encoding:
/// `0x7d ‖ rlp([to, input, salt])`, hash-verified against `tx_hash`.
///
/// Mirrors the consistency checker's construction: caller = bootloader
/// formal address, zero gas price / value / nonce, block gas limit (the
/// tx's own is zero and the handler rejects `gas_used_override` above the
/// limit), service tx type 0x7d (validation skipped).
fn build_system_tx(
    input: &TxInput,
    tx_hash: &B256,
    encoded_2718: &[u8],
    block_gas_limit: u64,
) -> (ZKsyncTx<TxEnv>, B256, u8) {
    // Authenticates the encoding against tx_hash and decodes (to, calldata).
    let (to, data) = decode_system_tx(tx_hash, encoded_2718);
    let to = revm::primitives::Address::from(to);

    let caller = revm::primitives::Address::from(BOOTLOADER_FORMAL_ADDRESS);

    let builder = TxEnv::builder()
        .caller(caller)
        .gas_limit(block_gas_limit)
        .gas_price(0)
        .gas_priority_fee(Some(0))
        .kind(revm::primitives::TxKind::Call(to))
        .value(U256::ZERO)
        .data(Bytes::from(data))
        .nonce(0)
        .tx_type(Some(SYSTEM_TX_TYPE))
        .chain_id(None)
        .blob_hashes(vec![]);

    let tx = ZKsyncTxBuilder::new()
        .base(builder)
        .mint(U256::ZERO)
        .refund_recipient(None)
        .gas_used_override(input.gas_used_override)
        .force_fail(input.force_fail)
        .tx_hash(*tx_hash)
        .build()
        .expect("failed to build system ZKsyncTx");

    (tx, *tx_hash, SYSTEM_TX_TYPE)
}

/// Parse one RLP item header at `pos`; returns (payload_start, payload_len).
/// Panics on malformed input — the encoding is hash-authenticated, so any
/// malformation is a witness-integrity failure, not a recoverable state.
fn rlp_header(buf: &[u8], pos: usize, expect_list: bool) -> (usize, usize) {
    assert!(pos < buf.len(), "RLP: truncated at header");
    let b = buf[pos];
    let (is_list, payload_start, payload_len) = match b {
        0x00..=0x7f => (false, pos, 1),
        0x80..=0xb7 => (false, pos + 1, (b - 0x80) as usize),
        0xb8..=0xbf => {
            let len_len = (b - 0xb7) as usize;
            let payload_len = rlp_len(buf, pos + 1, len_len);
            (false, pos + 1 + len_len, payload_len)
        }
        0xc0..=0xf7 => (true, pos + 1, (b - 0xc0) as usize),
        0xf8..=0xff => {
            let len_len = (b - 0xf7) as usize;
            let payload_len = rlp_len(buf, pos + 1, len_len);
            (true, pos + 1 + len_len, payload_len)
        }
    };
    assert_eq!(is_list, expect_list, "RLP: unexpected item kind");
    assert!(
        payload_start + payload_len <= buf.len(),
        "RLP: payload out of bounds"
    );
    (payload_start, payload_len)
}

/// Read a big-endian length of `len_len` bytes (long-form RLP headers).
fn rlp_len(buf: &[u8], pos: usize, len_len: usize) -> usize {
    assert!(len_len <= 8 && pos + len_len <= buf.len(), "RLP: bad length");
    buf[pos..pos + len_len]
        .iter()
        .fold(0usize, |acc, &b| (acc << 8) | b as usize)
}

// System tx call selectors (keccak256 of the canonical signatures, first 4
// bytes) and their protocol-defined target addresses — must stay in lockstep
// with zksync-os-server's `SystemTxInput`.
const SEL_ADD_INTEROP_ROOTS: [u8; 4] = [0xcc, 0xa2, 0xf7, 0xbc]; // addInteropRootsInBatch((uint256,uint256,bytes32[])[])
const SEL_SET_SL_CHAIN_ID: [u8; 4] = [0x04, 0x02, 0x03, 0xe6]; // setSettlementLayerChainId(uint256)
const SEL_SET_INTEROP_FEE: [u8; 4] = [0x08, 0x27, 0x3d, 0x8a]; // setInteropFee(uint256)

const L2_INTEROP_ROOT_STORAGE_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
];
const SYSTEM_CONTEXT_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x0b,
];
const L2_INTEROP_CENTER_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0d,
];

/// Authenticate a system tx encoding and decode its (to, calldata).
fn decode_system_tx(tx_hash: &B256, encoded_2718: &[u8]) -> ([u8; 20], Vec<u8>) {
    let computed = crate::hash::keccak256(encoded_2718);
    assert_eq!(
        computed, *tx_hash,
        "system tx hash mismatch: keccak256(encoded)={computed}, claimed={tx_hash}"
    );
    assert!(
        !encoded_2718.is_empty() && encoded_2718[0] == SYSTEM_TX_TYPE,
        "system tx type byte mismatch"
    );
    let rlp = &encoded_2718[1..];
    let (list_start, list_len) = rlp_header(rlp, 0, true);
    assert_eq!(list_start + list_len, rlp.len(), "system tx RLP has trailing bytes");
    let (to_start, to_len) = rlp_header(rlp, list_start, false);
    assert_eq!(to_len, 20, "system tx `to` must be a 20-byte address");
    let mut to = [0u8; 20];
    to.copy_from_slice(&rlp[to_start..to_start + 20]);
    let (input_start, input_len) = rlp_header(rlp, to_start + to_len, false);
    let data = rlp[input_start..input_start + input_len].to_vec();
    let (salt_start, salt_len) = rlp_header(rlp, input_start + input_len, false);
    assert!(salt_len <= 8, "system tx `salt` must fit in u64");
    assert_eq!(salt_start + salt_len, rlp.len(), "system tx RLP not fully consumed");
    (to, data)
}

/// Fold the interop roots of an `addInteropRootsInBatch` system tx into the
/// batch's dependency-roots rolling hash, exactly as the server's batch
/// builder does: `hash = keccak256(hash ‖ chainId ‖ blockOrBatchNumber ‖
/// sides…)` per root, in calldata order. Non-import system txs (SL-chain-id,
/// interop-fee updates) contribute nothing; unknown selectors are rejected.
pub(super) fn fold_system_tx_interop_roots(
    tx_hash: &B256,
    encoded_2718: &[u8],
    rolling_hash: &mut B256,
) {
    let (to, data) = decode_system_tx(tx_hash, encoded_2718);
    assert!(data.len() >= 4, "system tx calldata missing selector");
    let selector: [u8; 4] = data[..4].try_into().unwrap();
    match selector {
        SEL_ADD_INTEROP_ROOTS => {
            assert_eq!(to, L2_INTEROP_ROOT_STORAGE_ADDRESS, "interop import to wrong target");
            for (chain_id, block_or_batch, sides) in decode_interop_roots(&data[4..]) {
                let mut buf = Vec::with_capacity(96 + 32 * sides.len());
                buf.extend_from_slice(rolling_hash.as_slice());
                buf.extend_from_slice(&chain_id);
                buf.extend_from_slice(&block_or_batch);
                for side in &sides {
                    buf.extend_from_slice(side.as_slice());
                }
                *rolling_hash = crate::hash::keccak256(&buf);
            }
        }
        SEL_SET_SL_CHAIN_ID => {
            assert_eq!(to, SYSTEM_CONTEXT_ADDRESS, "SL-chain-id update to wrong target");
        }
        SEL_SET_INTEROP_FEE => {
            assert_eq!(to, L2_INTEROP_CENTER_ADDRESS, "interop-fee update to wrong target");
        }
        _ => panic!("unknown system transaction selector: {selector:02x?}"),
    }
}

/// Strict ABI decode of `InteropRoot[]` (`(uint256,uint256,bytes32[])[]`)
/// from post-selector calldata. Returns raw 32-byte words for the two
/// uint256 fields (only ever re-encoded into the rolling hash) plus sides.
fn decode_interop_roots(abi: &[u8]) -> Vec<([u8; 32], [u8; 32], Vec<B256>)> {
    let word = |off: usize| -> [u8; 32] {
        assert!(off + 32 <= abi.len(), "interop ABI: word out of bounds");
        abi[off..off + 32].try_into().unwrap()
    };
    let uword = |off: usize| -> usize {
        let w = word(off);
        assert!(w[..24].iter().all(|&b| b == 0), "interop ABI: offset/length too large");
        u64::from_be_bytes(w[24..].try_into().unwrap()) as usize
    };

    // Cap every pre-allocation at a value far above any legitimate count. The
    // element counts come from attacker-controlled ABI length words, so sizing a
    // Vec directly on them lets a few bytes request a multi-gigabyte allocation.
    // The cap only bounds the reservation; the loops below still push every real
    // element (and a bogus count runs out of bounds before it can grow the Vec).
    const MAX_PREALLOC: usize = 1 << 12;

    let array_off = uword(0);
    let n = uword(array_off);
    let elems_base = array_off + 32;
    let mut roots = Vec::with_capacity(n.min(MAX_PREALLOC));
    for i in 0..n {
        let struct_off = elems_base + uword(elems_base + 32 * i);
        let chain_id = word(struct_off);
        let block_or_batch = word(struct_off + 32);
        let sides_off = struct_off + uword(struct_off + 64);
        let m = uword(sides_off);
        let mut sides = Vec::with_capacity(m.min(MAX_PREALLOC));
        for j in 0..m {
            sides.push(B256::from(word(sides_off + 32 + 32 * j)));
        }
        roots.push((chain_id, block_or_batch, sides));
    }
    roots
}
