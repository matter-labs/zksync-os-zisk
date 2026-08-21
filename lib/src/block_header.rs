//! Block header hash computation (RLP encoding + Keccak256).
//!
//! Computes the ZKsync OS block header hash using the same Ethereum block
//! header format as `basic_bootloader::block_header::BlockHeader`. The RLP
//! field list, the field order and the keccak wrapper are the same on every
//! ZKsync OS line; only the two tree-root field VALUES depend on the spec.
//! Up to AtlasV3, `transactions_root` carries the keccak rolling hash of the
//! block's tx hashes and `receipts_root` is zero. From AtlasV4 both are
//! depth-32 Blake2s Merkle roots (see `crate::block_roots`). State root and
//! bloom are zero on every line.

use alloy_primitives::B256;

use crate::commitment::keccak256;

/// Keccak256(RLP([])) — the empty ommers hash (post-merge constant).
const EMPTY_OMMER_HASH: B256 = B256::new([
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67,
    0xb6, 0xcc, 0xd4, 0x1a, 0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13,
    0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
]);

/// Compute the ZKsync OS block header hash.
///
/// This is `keccak256(RLP([parent_hash, ommers_hash, beneficiary, state_root,
///   transactions_root, receipts_root, logs_bloom, difficulty, number,
///   gas_limit, gas_used, timestamp, extra_data, mix_hash, nonce, base_fee_per_gas]))`.
///
/// Fixed fields: `ommers_hash` = EMPTY_OMMER_HASH, `state_root` = 0, `receipts_root` = 0,
/// `logs_bloom` = 0, `difficulty` = 0, `extra_data` = empty, `nonce` = 0.
#[allow(clippy::too_many_arguments)]
pub fn compute_block_header_hash(
    parent_hash: &B256,
    beneficiary: &[u8; 20],
    transactions_root: &B256,
    receipts_root: &B256,
    number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    mix_hash: &B256,
    base_fee_per_gas: u64,
) -> B256 {
    let mut inner = Vec::with_capacity(650);

    rlp_encode_bytes(&mut inner, parent_hash.as_slice());
    rlp_encode_bytes(&mut inner, EMPTY_OMMER_HASH.as_slice());
    rlp_encode_bytes(&mut inner, beneficiary);
    rlp_encode_bytes(&mut inner, B256::ZERO.as_slice()); // state_root
    rlp_encode_bytes(&mut inner, transactions_root.as_slice());
    rlp_encode_bytes(&mut inner, receipts_root.as_slice()); // receipts_root
    rlp_encode_bytes(&mut inner, &[0u8; 256]); // logs_bloom
    rlp_encode_number(&mut inner, &[0u8; 32]); // difficulty
    rlp_encode_number(&mut inner, &number.to_be_bytes());
    rlp_encode_number(&mut inner, &gas_limit.to_be_bytes());
    rlp_encode_number(&mut inner, &gas_used.to_be_bytes());
    rlp_encode_number(&mut inner, &timestamp.to_be_bytes());
    rlp_encode_bytes(&mut inner, &[]); // extra_data
    rlp_encode_bytes(&mut inner, mix_hash.as_slice());
    rlp_encode_bytes(&mut inner, &[0u8; 8]); // nonce
    rlp_encode_number(&mut inner, &base_fee_per_gas.to_be_bytes());

    let mut buf = Vec::with_capacity(inner.len() + 5);
    rlp_encode_list_header(&mut buf, inner.len());
    buf.extend_from_slice(&inner);

    keccak256(&buf)
}

// ---------------------------------------------------------------------------
// Minimal RLP encoding (matching zksync-os's rlp module)
// ---------------------------------------------------------------------------

fn rlp_encode_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    if data.len() == 1 && data[0] < 0x80 {
        buf.push(data[0]);
    } else if data.len() < 56 {
        buf.push(0x80 + data.len() as u8);
        buf.extend_from_slice(data);
    } else {
        let len_bytes = be_bytes_trimmed(data.len());
        buf.push(0xb7 + len_bytes.len() as u8);
        buf.extend_from_slice(&len_bytes);
        buf.extend_from_slice(data);
    }
}

fn rlp_encode_number(buf: &mut Vec<u8>, be_bytes: &[u8]) {
    let stripped = strip_leading_zeros(be_bytes);
    if stripped.is_empty() {
        buf.push(0x80); // RLP encoding of zero = empty byte string
    } else {
        rlp_encode_bytes(buf, stripped);
    }
}

fn rlp_encode_list_header(buf: &mut Vec<u8>, content_len: usize) {
    if content_len < 56 {
        buf.push(0xc0 + content_len as u8);
    } else {
        let len_bytes = be_bytes_trimmed(content_len);
        buf.push(0xf7 + len_bytes.len() as u8);
        buf.extend_from_slice(&len_bytes);
    }
}

fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let first_nonzero = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[first_nonzero..]
}

/// Encode a usize as minimal big-endian bytes.
fn be_bytes_trimmed(val: usize) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

/// Keccak256 of the empty input — the AtlasV3 rolling-hash seed.
pub const KECCAK_EMPTY: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2,
    0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
    0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);

/// Native transactions commitment: `keccak256(rolling ‖ tx_hash)` folded over
/// the block's tx hashes. This value is the header's `transactions_root`.
///
/// The seed is version-dependent: zksync-os up to v0.2.x (AtlasV1/V2,
/// `bootloader/mod.rs` `tx_rolling_hash = [0u8; 32]`) starts from zero, while
/// v0.3.x (AtlasV3, `TransactionsRollingKeccakHasher::empty()`) starts from
/// `keccak256([])`.
pub fn transactions_rolling_hash(tx_hashes: &[B256], seed: B256) -> B256 {
    let mut rolling = seed;
    for tx_hash in tx_hashes {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(rolling.as_slice());
        buf[32..].copy_from_slice(tx_hash.as_slice());
        rolling = keccak256(&buf);
    }
    rolling
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_empty_constant_matches_keccak_of_empty_input() {
        assert_eq!(KECCAK_EMPTY, keccak256(&[]));
    }

    #[test]
    fn rolling_hash_of_no_txs_returns_the_seed() {
        assert_eq!(transactions_rolling_hash(&[], B256::ZERO), B256::ZERO);
        assert_eq!(transactions_rolling_hash(&[], KECCAK_EMPTY), KECCAK_EMPTY);
    }

    #[test]
    fn rolling_hash_folds_seed_then_tx_hashes() {
        let tx = B256::repeat_byte(0x11);
        let mut buf = [0u8; 64];
        buf[32..].copy_from_slice(tx.as_slice());
        let expected_zero_seed = keccak256(&buf);
        assert_eq!(transactions_rolling_hash(&[tx], B256::ZERO), expected_zero_seed);

        buf[..32].copy_from_slice(KECCAK_EMPTY.as_slice());
        let expected_keccak_seed = keccak256(&buf);
        assert_eq!(transactions_rolling_hash(&[tx], KECCAK_EMPTY), expected_keccak_seed);
        assert_ne!(expected_zero_seed, expected_keccak_seed);
    }
}
