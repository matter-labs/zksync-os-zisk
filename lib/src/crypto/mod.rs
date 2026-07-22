#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
use revm::precompile::DefaultCrypto;

mod ffi;
mod impls;

#[derive(Debug)]
pub struct CustomEvmCrypto {
    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    default_crypto: DefaultCrypto,
}

impl Default for CustomEvmCrypto {
    fn default() -> Self {
        Self {
            #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
            default_crypto: DefaultCrypto,
        }
    }
}

/// Install [`CustomEvmCrypto`] as alloy-consensus's global signature-recovery
/// backend.
///
/// `revm::install_crypto` only covers REVM *precompiles*. Transaction-envelope
/// recovery (`TxEnvelope::recover_signer` in [`crate::executor`]) instead
/// dispatches through alloy-consensus's own [`alloy_consensus::crypto::CryptoProvider`].
/// Without this install, that path falls back to software k256 — the dominant
/// ZiSK proving cost. Installing the provider routes tx recovery through the
/// ZiSK-accelerated secp256k1 circuits (via `secp256k1_ecdsa_address_recover_c`).
///
/// Idempotent: a prior or concurrent install is ignored (the backend is a
/// write-once cell).
pub fn install_tx_recovery_provider() {
    alloy_consensus::crypto::install_default_provider(std::sync::Arc::new(
        CustomEvmCrypto::default(),
    ))
    .ok();
}
