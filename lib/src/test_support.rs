//! Helpers shared by the crate's unit tests.

use revm::primitives::{Address, U256};

/// Chain id of the transactions [`sign_legacy`] signs.
pub(crate) const TEST_CHAIN_ID: u64 = 1;
/// Gas price of the transactions [`sign_legacy`] signs.
pub(crate) const TEST_GAS_PRICE: u128 = 10;

/// Sign a legacy transaction (chain [`TEST_CHAIN_ID`], gas price
/// [`TEST_GAS_PRICE`], no value) with the key `sk_bytes`, and return the
/// sender and the EIP-2718 encoding.
pub(crate) fn sign_legacy(
    sk_bytes: [u8; 32],
    nonce: u64,
    kind: alloy_primitives::TxKind,
    data: Vec<u8>,
    gas_limit: u64,
) -> (Address, Vec<u8>) {
    use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
    use alloy_eips::eip2718::Encodable2718;
    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_bytes((&sk_bytes).into()).unwrap();
    let pubkey = sk.verifying_key().to_encoded_point(false);
    let sender = Address::from_slice(&alloy_primitives::keccak256(&pubkey.as_bytes()[1..])[12..]);
    let tx = TxLegacy {
        chain_id: Some(TEST_CHAIN_ID),
        nonce,
        gas_price: TEST_GAS_PRICE,
        gas_limit,
        to: kind,
        value: U256::ZERO,
        input: data.into(),
    };
    let (sig, recid) = sk.sign_prehash_recoverable(tx.signature_hash().as_slice()).unwrap();
    let sig_bytes = sig.to_bytes();
    let signature = alloy_primitives::Signature::new(
        U256::from_be_slice(&sig_bytes[..32]),
        U256::from_be_slice(&sig_bytes[32..]),
        recid.is_y_odd(),
    );
    let mut signed = Vec::new();
    TxEnvelope::Legacy(tx.into_signed(signature)).encode_2718(&mut signed);
    (sender, signed)
}
