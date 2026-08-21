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
/// `max_tx_gas_limit` is the chain-config EIP-7825 per-tx cap; `None` means the
/// spec applies no such cap, and the block gas limit is the only bound on an L2
/// transaction (see `build_l2_tx`).
///
/// Public so host-side witness builders (the dump-to-BatchInput reader) can
/// run their read-discovery pass through the exact same tx construction the
/// guest uses, instead of maintaining a drifting replica.
pub fn build_proven_tx(
    input: &TxInput,
    block_gas_limit: u64,
    max_tx_gas_limit: Option<u64>,
) -> (ZKsyncTx<TxEnv>, B256, u8) {
    match &input.auth {
        TxAuth::L1 { tx_hash, abi_encoded } | TxAuth::Upgrade { tx_hash, abi_encoded } => {
            build_l1_upgrade_tx(input, tx_hash, abi_encoded)
        }
        // The effective per-tx cap native enforces for L2 transactions is the
        // smaller of the block gas limit and the chain-config `max_tx_gas_limit`
        // (`System::get_individual_tx_gas_limit`).
        TxAuth::L2 { signed_bytes } => build_l2_tx(
            input,
            signed_bytes,
            max_tx_gas_limit.map_or(block_gas_limit, |cap| block_gas_limit.min(cap)),
        ),
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
fn build_l2_tx(
    input: &TxInput,
    signed_bytes: &[u8],
    individual_tx_gas_limit: u64,
) -> (ZKsyncTx<TxEnv>, B256, u8) {
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

    // Reject a transaction whose gas limit exceeds the effective per-tx cap.
    // Native runs this check for every L2 transaction in `process_l2_transaction`
    // (`validate_and_compute_fee_for_transaction`): it rejects the transaction
    // with `CallerGasLimitMoreThanTxLimit` when `gas_limit > min(block_gas_limit,
    // max_tx_gas_limit)`. L1, upgrade and system transactions take other paths
    // that do not apply this cap, so only the L2 path enforces it here.
    // `max_tx_gas_limit` is committed into `chain_config_hash`; without this
    // check the guest would execute a transaction that native rejects. On a
    // spec that carries no EIP-7825 cap the caller passes the block gas limit,
    // which native still enforces.
    assert!(
        gas_limit <= individual_tx_gas_limit,
        "L2 tx gas limit {gas_limit} exceeds the per-tx cap {individual_tx_gas_limit} \
         (the block gas limit, narrowed by the chain max_tx_gas_limit on a spec \
          that applies EIP-7825)"
    );
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
const SEL_SET_SL_CHAIN_ID: [u8; 4] = [0x04, 0x02, 0x03, 0xe6]; // setSettlementLayerChainId(uint256)
const SEL_SET_INTEROP_FEE: [u8; 4] = [0x08, 0x27, 0x3d, 0x8a]; // setInteropFee(uint256)

/// The `addInteropRootsInBatch` ABI the spec's L2InteropRootStorage exposes.
/// Native whitelists exactly one `(to, selector)` pair per line, so a batch
/// carrying the other spec's import is rejected as an unknown selector.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum InteropImportAbi {
    /// AtlasV1 through AtlasV3:
    /// `addInteropRootsInBatch((uint256,uint256,bytes32[])[])`.
    WithoutTimestamp,
    /// AtlasV4: the `InteropRoot` tuple carries the root's creation timestamp,
    /// `addInteropRootsInBatch((uint256,uint256,uint256,bytes32[])[])`.
    WithTimestamp,
}

impl InteropImportAbi {
    /// The first four bytes of the keccak256 of the canonical signature.
    fn selector(self) -> [u8; 4] {
        match self {
            Self::WithoutTimestamp => [0xcc, 0xa2, 0xf7, 0xbc],
            Self::WithTimestamp => [0xc1, 0x7a, 0x9f, 0xbd],
        }
    }

    /// Size of the tuple's static head, which is where the `sides` offset word
    /// sits: three words without the timestamp, four with it.
    fn static_head_len(self) -> usize {
        match self {
            Self::WithoutTimestamp => 96,
            Self::WithTimestamp => 128,
        }
    }
}

/// One imported interop root, as the raw ABI words the rolling hash re-encodes.
struct ImportedInteropRoot {
    chain_id: [u8; 32],
    block_or_batch_number: [u8; 32],
    /// The root's creation timestamp on the source chain, present when the
    /// spec's ABI carries it.
    timestamp: Option<[u8; 32]>,
    sides: Vec<B256>,
}

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
/// batch's dependency-roots rolling hash, mirroring native
/// `calculate_interop_roots_rolling_hash`: `hash = keccak256(hash ‖ chainId ‖
/// blockOrBatchNumber ‖ [timestamp] ‖ sides…)` per root, in calldata order. The
/// timestamp word is present from AtlasV4 on, and the settlement layer hashes
/// the same preimage in `ExecutorFacet._verifyDependencyInteropRoots`.
///
/// Non-import system txs (SL-chain-id, interop-fee updates) contribute nothing;
/// unknown selectors are rejected.
pub(super) fn fold_system_tx_interop_roots(
    tx_hash: &B256,
    encoded_2718: &[u8],
    import_abi: InteropImportAbi,
    rolling_hash: &mut B256,
) {
    let (to, data) = decode_system_tx(tx_hash, encoded_2718);
    assert!(data.len() >= 4, "system tx calldata missing selector");
    let selector: [u8; 4] = data[..4].try_into().unwrap();
    if selector == import_abi.selector() {
        assert_eq!(to, L2_INTEROP_ROOT_STORAGE_ADDRESS, "interop import to wrong target");
        for root in decode_interop_roots(&data[4..], import_abi) {
            let mut buf = Vec::with_capacity(import_abi.static_head_len() + 32 * root.sides.len());
            buf.extend_from_slice(rolling_hash.as_slice());
            buf.extend_from_slice(&root.chain_id);
            buf.extend_from_slice(&root.block_or_batch_number);
            if let Some(timestamp) = root.timestamp {
                buf.extend_from_slice(&timestamp);
            }
            for side in &root.sides {
                buf.extend_from_slice(side.as_slice());
            }
            *rolling_hash = crate::hash::keccak256(&buf);
        }
        return;
    }
    match selector {
        SEL_SET_SL_CHAIN_ID => {
            assert_eq!(to, SYSTEM_CONTEXT_ADDRESS, "SL-chain-id update to wrong target");
        }
        SEL_SET_INTEROP_FEE => {
            assert_eq!(to, L2_INTEROP_CENTER_ADDRESS, "interop-fee update to wrong target");
        }
        _ => panic!("unknown system transaction selector: {selector:02x?}"),
    }
}

/// Strict ABI decode of `InteropRoot[]` from post-selector calldata. Returns
/// raw 32-byte words for the uint256 fields (only ever re-encoded into the
/// rolling hash) plus sides.
fn decode_interop_roots(abi: &[u8], import_abi: InteropImportAbi) -> Vec<ImportedInteropRoot> {
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
    // The `sides` offset word is the last word of the tuple's static head.
    let sides_offset_word = import_abi.static_head_len() - 32;
    let mut roots = Vec::with_capacity(n.min(MAX_PREALLOC));
    for i in 0..n {
        let struct_off = elems_base + uword(elems_base + 32 * i);
        let chain_id = word(struct_off);
        let block_or_batch_number = word(struct_off + 32);
        let timestamp = match import_abi {
            InteropImportAbi::WithoutTimestamp => None,
            InteropImportAbi::WithTimestamp => Some(word(struct_off + 64)),
        };
        let sides_off = struct_off + uword(struct_off + sides_offset_word);
        let m = uword(sides_off);
        let mut sides = Vec::with_capacity(m.min(MAX_PREALLOC));
        for j in 0..m {
            sides.push(B256::from(word(sides_off + 32 + 32 * j)));
        }
        roots.push(ImportedInteropRoot {
            chain_id,
            block_or_batch_number,
            timestamp,
            sides,
        });
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The chain-config per-tx cap default (`1 << 24`), matching native's
    /// `DEFAULT_MAX_TX_GAS_LIMIT` and the server's `max_tx_gas_limit` default.
    const MAX_TX_GAS_LIMIT: u64 = 1 << 24;

    /// Sign a legacy L2 transaction with the given gas limit and return its
    /// EIP-2718 encoding, ready for `TxAuth::L2`.
    fn signed_l2_tx(gas_limit: u64) -> Vec<u8> {
        use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
        use alloy_eips::eip2718::Encodable2718;
        use k256::ecdsa::SigningKey;

        let sk = SigningKey::from_bytes((&[0x11u8; 32]).into()).unwrap();
        let to = revm::primitives::Address::from([0x22u8; 20]);
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 0,
            gas_price: 10,
            gas_limit,
            to: revm::primitives::TxKind::Call(to),
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
        let mut signed = Vec::new();
        envelope.encode_2718(&mut signed);
        signed
    }

    fn l2_input(signed_bytes: Vec<u8>) -> TxInput {
        TxInput {
            chain_id: Some(1),
            gas_used_override: None,
            force_fail: false,
            auth: TxAuth::L2 { signed_bytes },
        }
    }

    /// An L2 transaction whose gas limit exceeds `max_tx_gas_limit` must be
    /// rejected when the block gas limit is not the smaller bound.
    #[test]
    #[should_panic(expected = "exceeds the per-tx cap")]
    fn rejects_l2_gas_limit_over_max_tx_cap() {
        let input = l2_input(signed_l2_tx(MAX_TX_GAS_LIMIT + 1));
        // Block gas limit is huge, so the chain cap is the binding bound.
        build_proven_tx(&input, u64::MAX, Some(MAX_TX_GAS_LIMIT));
    }

    /// The effective cap is the SMALLER of the block gas limit and the chain
    /// cap: a transaction under `max_tx_gas_limit` but over the block gas limit
    /// is still rejected.
    #[test]
    #[should_panic(expected = "exceeds the per-tx cap")]
    fn rejects_l2_gas_limit_over_block_gas_limit() {
        let input = l2_input(signed_l2_tx(2_000_000));
        // Block gas limit is the binding bound here.
        build_proven_tx(&input, 1_000_000, Some(MAX_TX_GAS_LIMIT));
    }

    /// A transaction whose gas limit equals the cap is accepted: the relation
    /// is `<=`, matching native's `tx_gas_limit <= individual_tx_gas_limit`.
    #[test]
    fn accepts_l2_gas_limit_at_cap() {
        let input = l2_input(signed_l2_tx(MAX_TX_GAS_LIMIT));
        // Building must not panic: the tx sits exactly at the cap.
        let (_tx, _hash, tx_type) = build_proven_tx(&input, u64::MAX, Some(MAX_TX_GAS_LIMIT));
        assert_eq!(tx_type, 0, "legacy L2 tx is type 0");
    }

    /// A spec without EIP-7825 applies no chain-config cap: a transaction above
    /// `max_tx_gas_limit` but inside the block gas limit is accepted. Native on
    /// the released v30 and v31 lines has no `ChainConfig::max_tx_gas_limit`, so
    /// an in-guest rejection there would make a legitimate batch unprovable.
    #[test]
    fn accepts_l2_gas_limit_over_chain_cap_without_eip7825() {
        let input = l2_input(signed_l2_tx(MAX_TX_GAS_LIMIT + 1));
        let (_tx, _hash, tx_type) = build_proven_tx(&input, u64::MAX, None);
        assert_eq!(tx_type, 0, "legacy L2 tx is type 0");
    }

    /// The block gas limit bounds an L2 transaction on every spec, so it still
    /// rejects an over-large transaction when no EIP-7825 cap applies.
    #[test]
    #[should_panic(expected = "exceeds the per-tx cap")]
    fn rejects_l2_gas_limit_over_block_gas_limit_without_eip7825() {
        let input = l2_input(signed_l2_tx(2_000_000));
        build_proven_tx(&input, 1_000_000, None);
    }

    /// The type byte this builder reports enters every AtlasV4 receipt leaf, so
    /// it must equal native's own class byte. The L2 path takes it from the
    /// envelope, whose discriminants are the EIP type numbers; the L1 and
    /// upgrade paths take it from the hash-authenticated ABI encoding; the
    /// system path is the protocol constant.
    #[test]
    fn transaction_type_bytes_match_the_native_classes() {
        use alloy_consensus::TxType;

        assert_eq!(TxType::Legacy as u8, 0);
        assert_eq!(TxType::Eip2930 as u8, 1);
        assert_eq!(TxType::Eip1559 as u8, 2);
        assert_eq!(TxType::Eip4844 as u8, 3);
        assert_eq!(TxType::Eip7702 as u8, 4);
        assert_eq!(SYSTEM_TX_TYPE, 0x7d);

        // The plumbing: a legacy envelope reports 0.
        let (_tx, _hash, tx_type) = build_proven_tx(&l2_input(signed_l2_tx(21_000)), u64::MAX, None);
        assert_eq!(tx_type, 0);

        // The L1 and upgrade paths report the ABI's `txType` word verbatim.
        for claimed in [0x7fu8, 0x7e] {
            let mut abi = vec![0u8; 32 + 19 * 32 + 5 * 32];
            abi[31] = 0x20; // outer offset
            abi[32 + 31] = claimed; // txType
            let dyn_base = 19u32 * 32;
            for j in 0..5u32 {
                let off = 32 + (14 + j as usize) * 32;
                abi[off + 28..off + 32].copy_from_slice(&(dyn_base + j * 32).to_be_bytes());
            }
            let tx_hash = crate::hash::keccak256(&abi);
            let input = TxInput {
                chain_id: Some(1),
                gas_used_override: None,
                force_fail: false,
                auth: TxAuth::L1 { tx_hash, abi_encoded: abi },
            };
            let (_tx, _hash, tx_type) = build_proven_tx(&input, u64::MAX, None);
            assert_eq!(tx_type, claimed);
        }
    }

    // ---- interop-root import: ABI encoding and the rolling-hash preimage ----

    /// Minimal RLP string encoding, for the system-tx envelope below.
    fn rlp_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if bytes.len() == 1 && bytes[0] < 0x80 {
            out.push(bytes[0]);
        } else if bytes.len() <= 55 {
            out.push(0x80 + bytes.len() as u8);
            out.extend_from_slice(bytes);
        } else {
            let len = bytes.len().to_be_bytes();
            let lead = len.iter().position(|&b| b != 0).unwrap();
            out.push(0xb7 + (len.len() - lead) as u8);
            out.extend_from_slice(&len[lead..]);
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Minimal RLP list encoding over already-encoded items.
    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut out = Vec::new();
        if payload.len() <= 55 {
            out.push(0xc0 + payload.len() as u8);
        } else {
            let len = payload.len().to_be_bytes();
            let lead = len.iter().position(|&b| b != 0).unwrap();
            out.push(0xf7 + (len.len() - lead) as u8);
            out.extend_from_slice(&len[lead..]);
        }
        out.extend_from_slice(&payload);
        out
    }

    /// ABI-encode `addInteropRootsInBatch` for a single `InteropRoot` holding
    /// one side, under the tuple shape `import_abi` describes.
    fn import_calldata(
        import_abi: InteropImportAbi,
        chain_id: u64,
        block_or_batch_number: u64,
        timestamp: u64,
        side: B256,
    ) -> Vec<u8> {
        let head = import_abi.static_head_len();
        let mut abi = Vec::new();
        let push_word = |abi: &mut Vec<u8>, value: u64| {
            abi.extend_from_slice(&[0u8; 24]);
            abi.extend_from_slice(&value.to_be_bytes());
        };
        push_word(&mut abi, 32); // offset of the InteropRoot[] array
        push_word(&mut abi, 1); // one element
        push_word(&mut abi, 32); // that element's offset, relative to elems_base
        push_word(&mut abi, chain_id);
        push_word(&mut abi, block_or_batch_number);
        if import_abi == InteropImportAbi::WithTimestamp {
            push_word(&mut abi, timestamp);
        }
        push_word(&mut abi, head as u64); // sides offset, relative to struct_off
        push_word(&mut abi, 1); // one side
        abi.extend_from_slice(side.as_slice());

        let mut calldata = import_abi.selector().to_vec();
        calldata.extend_from_slice(&abi);
        calldata
    }

    /// Wrap `calldata` in the hash-authenticated system-tx envelope
    /// `0x7d ‖ rlp([to, input, salt])` addressed to L2InteropRootStorage.
    fn import_system_tx(calldata: Vec<u8>) -> (B256, Vec<u8>) {
        let mut encoded = vec![SYSTEM_TX_TYPE];
        encoded.extend_from_slice(&rlp_list(&[
            rlp_string(&L2_INTEROP_ROOT_STORAGE_ADDRESS),
            rlp_string(&calldata),
            rlp_string(&[]),
        ]));
        (crate::hash::keccak256(&encoded), encoded)
    }

    /// Fold one imported root and report the resulting rolling hash.
    fn fold_one_import(
        import_abi: InteropImportAbi,
        chain_id: u64,
        block_or_batch_number: u64,
        timestamp: u64,
        side: B256,
    ) -> B256 {
        let (tx_hash, encoded) = import_system_tx(import_calldata(
            import_abi,
            chain_id,
            block_or_batch_number,
            timestamp,
            side,
        ));
        let mut rolling = B256::ZERO;
        fold_system_tx_interop_roots(&tx_hash, &encoded, import_abi, &mut rolling);
        rolling
    }

    /// The AtlasV4 preimage is `prev ‖ chainId ‖ blockOrBatchNumber ‖ timestamp
    /// ‖ root`, 160 bytes, matching native
    /// `calculate_interop_roots_rolling_hash` and the settlement layer's
    /// `abi.encodePacked(prev, chainId, blockOrBatchNumber, timestamp, sides)`.
    #[test]
    fn interop_rolling_hash_folds_the_native_preimage() {
        let side = B256::repeat_byte(0xab);
        let word = |value: u64| {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&value.to_be_bytes());
            w
        };
        let mut preimage = Vec::new();
        preimage.extend_from_slice(B256::ZERO.as_slice());
        preimage.extend_from_slice(&word(37));
        preimage.extend_from_slice(&word(11));
        preimage.extend_from_slice(&word(1_700_000_000));
        preimage.extend_from_slice(side.as_slice());
        assert_eq!(preimage.len(), 160);

        assert_eq!(
            fold_one_import(
                InteropImportAbi::WithTimestamp,
                37,
                11,
                1_700_000_000,
                side
            ),
            crate::hash::keccak256(&preimage),
        );
    }

    /// The timestamp reaches the committed value: two roots that differ only in
    /// their creation timestamp fold to different rolling hashes, and the
    /// timestamp-less tuple folds to a third value even at timestamp zero.
    #[test]
    fn interop_rolling_hash_commits_the_timestamp() {
        let side = B256::repeat_byte(0xab);
        let with_zero = fold_one_import(InteropImportAbi::WithTimestamp, 37, 11, 0, side);
        let with_value = fold_one_import(InteropImportAbi::WithTimestamp, 37, 11, 7, side);
        let without = fold_one_import(InteropImportAbi::WithoutTimestamp, 37, 11, 0, side);
        assert_ne!(with_zero, with_value);
        assert_ne!(with_zero, without);
    }

    /// Native whitelists one `(to, selector)` pair per line, so each spec
    /// rejects the other's import as an unknown selector rather than decoding
    /// it under the wrong tuple shape.
    #[test]
    fn interop_import_selector_is_spec_gated() {
        for (encoded_abi, expected_abi) in [
            (InteropImportAbi::WithTimestamp, InteropImportAbi::WithoutTimestamp),
            (InteropImportAbi::WithoutTimestamp, InteropImportAbi::WithTimestamp),
        ] {
            let (tx_hash, encoded) = import_system_tx(import_calldata(
                encoded_abi,
                37,
                11,
                0,
                B256::repeat_byte(0xab),
            ));
            let mut rolling = B256::ZERO;
            let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                fold_system_tx_interop_roots(&tx_hash, &encoded, expected_abi, &mut rolling)
            }));
            assert!(
                rejected.is_err(),
                "{encoded_abi:?} import must not decode under {expected_abi:?}",
            );
        }
    }
}
