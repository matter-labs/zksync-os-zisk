//! Off-chain verification helpers for ZKsync OS ZiSK proofs.
//!
//! The server produces a ZiSK proof for each batch (the final BN254 PLONK
//! wrap, 768 bytes) with 576 bytes of public values, then submits both to L1.
//! This crate lets the server check the proof off-chain BEFORE it submits, so a
//! bad proof fails fast on the box instead of on-chain.
//!
//! # What this crate verifies, and what it does NOT
//!
//! The pinned ZiSK toolchain does NOT expose a pure-Rust verifier for
//! the final BN254 PLONK proof. `cargo-zisk verify` and `zisk_common::Proof::
//! verify` both check the PLONK wrap by shelling out to the external `snarkjs`
//! Node.js CLI (see `proofman::verify_snark_proof`). So a dependency-light,
//! native BN254 PLONK pairing check is not available today.
//!
//! Because of that, this crate splits into two layers:
//!
//! - [`verify_plonk`] / [`verify_aggregated_range`] (base, only SHA-256 +
//!   256-bit integer): they reproduce every check the on-chain `ZiskVerifier`
//!   runs BEFORE the pairing — the wire lengths, the `programVK` / `rootC
//!   VadcopFinal` binding (with [`verify_plonk_bound`]), and the single public
//!   signal `sha256(public_values) mod r`. These catch the common fail-fast
//!   cases (a wrong guest program, a wrong SNARK setup, a malformed or
//!   truncated wire artifact) cheaply and natively. They do NOT run the BN254
//!   pairing, so they cannot reject a well-shaped proof that fails the pairing.
//!   Treat a success as "the wire artifact is on-chain-decodable and binds the
//!   expected keys", NOT as "the SNARK is valid".
//!
//! - [`verify_vadcop_final_stream`] (feature `stark-native`): the native,
//!   pure-Rust verifier for the intermediate `vadcop_final` STARK proof, via
//!   pil2-proofman's `proofman-verifier`. This IS a full cryptographic check,
//!   but of the STARK layer, not the PLONK wrap. It applies to the aggregated
//!   lane's per-batch streams (the prover holds these before it aggregates
//!   them). The final per-batch PLONK the server submits does not carry the
//!   STARK proof, so this does not cover the per-batch submit path.
//!
//! # On-chain layout (mirrored here)
//!
//! The 576-byte public values decode as
//! `programVK(32) ‖ guest publics(512) ‖ rootCVadcopFinal(32)`. The circuit's
//! single public signal is `uint256(sha256(public_values)) mod r`, with `r` the
//! BN254 scalar-field modulus. See `ZiskVerifier.sol`.

use sha2::{Digest, Sha256};

/// BN254 scalar-field integer (256 bits, 4 limbs).
type U256 = ruint::Uint<256, 4>;

/// The final BN254 PLONK proof size: 24 field elements, 32 bytes each.
pub const PLONK_PROOF_BYTES: usize = 768;

/// The ZiSK public-values size: `programVK(32) ‖ guest publics(512) ‖
/// rootCVadcopFinal(32)`.
pub const PUBLIC_VALUES_BYTES: usize = 576;

/// Byte range of the `programVK` (the guest ELF ROM root) in the public values.
pub const PROGRAM_VK_RANGE: core::ops::Range<usize> = 0..32;

/// Byte range of the guest publics (ziskos's 64-word output block, each word
/// 8 little-endian bytes).
pub const GUEST_PUBLICS_RANGE: core::ops::Range<usize> = 32..544;

/// Byte range of the `rootCVadcopFinal` (the vadcop-final VK) in the public
/// values.
pub const ROOT_C_VADCOP_FINAL_RANGE: core::ops::Range<usize> = 544..576;

/// The BN254 scalar-field modulus `r`, big-endian.
/// `21888242871839275222246405745257275088548364400416034343698204186575808495617`.
pub const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// The pinned `programVK` and `rootCVadcopFinal` a proof must bind. Pass this to
/// [`verify_plonk_bound`] / [`verify_aggregated_range_bound`] to reject a proof
/// that attests to a different guest program or a different SNARK setup.
///
/// Both values rotate every time the guest ELF or the recursive setup changes,
/// so the caller supplies them (the server reads them from its configured
/// `ProvingVersion`); this crate bakes in no stale key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedProgram {
    /// The guest ELF ROM root, 32 bytes big-endian (wire bytes `[0..32]`).
    pub program_vk: [u8; 32],
    /// The vadcop-final VK, 32 bytes big-endian (wire bytes `[544..576]`).
    pub root_c_vadcop_final: [u8; 32],
}

/// A verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The PLONK proof is not [`PLONK_PROOF_BYTES`] long.
    ProofLength { got: usize },
    /// The public values are not [`PUBLIC_VALUES_BYTES`] long.
    PublicValuesLength { got: usize },
    /// The public values' `programVK` prefix differs from the expected one.
    ProgramVkMismatch,
    /// The public values' `rootCVadcopFinal` suffix differs from the expected
    /// one.
    RootCVadcopFinalMismatch,
    /// The serialized `vadcop_final` stream is malformed (feature
    /// `stark-native`). The string carries the parser's reason.
    StreamMalformed(String),
    /// The `vadcop_final` STARK proof failed cryptographic verification
    /// (feature `stark-native`).
    StarkInvalid,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::ProofLength { got } => {
                write!(
                    f,
                    "PLONK proof must be {PLONK_PROOF_BYTES} bytes, got {got}"
                )
            }
            VerifyError::PublicValuesLength { got } => write!(
                f,
                "public values must be {PUBLIC_VALUES_BYTES} bytes, got {got}"
            ),
            VerifyError::ProgramVkMismatch => {
                write!(f, "programVK does not match the expected guest program")
            }
            VerifyError::RootCVadcopFinalMismatch => {
                write!(f, "rootCVadcopFinal does not match the expected setup")
            }
            VerifyError::StreamMalformed(why) => write!(f, "malformed vadcop_final stream: {why}"),
            VerifyError::StarkInvalid => write!(f, "vadcop_final STARK proof was not verified"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Check the wire form of a final PLONK artifact: the proof length and the
/// public-values length.
fn check_wire_form(proof: &[u8], public_values: &[u8]) -> Result<(), VerifyError> {
    if proof.len() != PLONK_PROOF_BYTES {
        return Err(VerifyError::ProofLength { got: proof.len() });
    }
    if public_values.len() != PUBLIC_VALUES_BYTES {
        return Err(VerifyError::PublicValuesLength {
            got: public_values.len(),
        });
    }
    Ok(())
}

/// Compute the circuit's single public signal, `uint256(sha256(public_values))
/// mod r`, exactly as the on-chain `ZiskVerifier` does before it calls the
/// PLONK verifier. Returns the 32-byte big-endian value.
///
/// This is the value the on-chain PLONK verifier consumes. The server can log
/// it, compare it, or feed it to an external verifier.
pub fn public_signal(public_values: &[u8]) -> Result<[u8; 32], VerifyError> {
    if public_values.len() != PUBLIC_VALUES_BYTES {
        return Err(VerifyError::PublicValuesLength {
            got: public_values.len(),
        });
    }
    let digest = Sha256::digest(public_values);
    let value = U256::from_be_bytes::<32>(digest.into());
    let modulus = U256::from_be_bytes::<32>(BN254_FR_MODULUS_BE);
    Ok((value % modulus).to_be_bytes::<32>())
}

/// Read the `programVK` prefix (wire bytes `[0..32]`) from the public values.
pub fn program_vk(public_values: &[u8]) -> Result<[u8; 32], VerifyError> {
    if public_values.len() != PUBLIC_VALUES_BYTES {
        return Err(VerifyError::PublicValuesLength {
            got: public_values.len(),
        });
    }
    Ok(public_values[PROGRAM_VK_RANGE].try_into().unwrap())
}

/// Read the `rootCVadcopFinal` suffix (wire bytes `[544..576]`) from the public
/// values.
pub fn root_c_vadcop_final(public_values: &[u8]) -> Result<[u8; 32], VerifyError> {
    if public_values.len() != PUBLIC_VALUES_BYTES {
        return Err(VerifyError::PublicValuesLength {
            got: public_values.len(),
        });
    }
    Ok(public_values[ROOT_C_VADCOP_FINAL_RANGE].try_into().unwrap())
}

/// Check a per-batch final PLONK proof's wire form.
///
/// This validates the proof length and the public-values length and confirms
/// the public signal is derivable. It reproduces the on-chain `ZiskVerifier`
/// decode UP TO the BN254 pairing. It does NOT run the pairing (no native
/// pure-Rust BN254 PLONK verifier is available; see the crate docs), so a
/// success means the artifact is on-chain-decodable, NOT that the SNARK is
/// valid. Use [`verify_plonk_bound`] to also bind the expected keys.
pub fn verify_plonk(proof: &[u8], public_values: &[u8]) -> Result<(), VerifyError> {
    check_wire_form(proof, public_values)?;
    // Confirm the public signal is derivable (it is, for a valid length).
    let _ = public_signal(public_values)?;
    Ok(())
}

/// Check a per-batch final PLONK proof AND bind it to the expected program.
///
/// In addition to [`verify_plonk`], this asserts the public values open with
/// `expected.program_vk` and close with `expected.root_c_vadcop_final` — the
/// on-chain `_proof[24] == programVK()` and `_proof[33] == rootCVadcopFinal()`
/// checks. It rejects a proof that attests to a different guest program or a
/// different SNARK setup. It still does NOT run the BN254 pairing.
pub fn verify_plonk_bound(
    proof: &[u8],
    public_values: &[u8],
    expected: &ExpectedProgram,
) -> Result<(), VerifyError> {
    verify_plonk(proof, public_values)?;
    if public_values[PROGRAM_VK_RANGE] != expected.program_vk {
        return Err(VerifyError::ProgramVkMismatch);
    }
    if public_values[ROOT_C_VADCOP_FINAL_RANGE] != expected.root_c_vadcop_final {
        return Err(VerifyError::RootCVadcopFinalMismatch);
    }
    Ok(())
}

/// Check an aggregated-range final PLONK proof's wire form.
///
/// The aggregated-range proof (the aggregator guest over N per-batch streams,
/// with the PLONK wrap) has the same 768/576 wire shape as a per-batch proof,
/// so the same checks apply. As with [`verify_plonk`], this does NOT run the
/// BN254 pairing.
pub fn verify_aggregated_range(proof: &[u8], public_values: &[u8]) -> Result<(), VerifyError> {
    verify_plonk(proof, public_values)
}

/// Check an aggregated-range final PLONK proof AND bind it to the expected
/// program. See [`verify_plonk_bound`].
pub fn verify_aggregated_range_bound(
    proof: &[u8],
    public_values: &[u8],
    expected: &ExpectedProgram,
) -> Result<(), VerifyError> {
    verify_plonk_bound(proof, public_values, expected)
}

#[cfg(feature = "stark-native")]
mod stark;
#[cfg(feature = "stark-native")]
pub use stark::{verify_vadcop_final_proof_file, verify_vadcop_final_stream};

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the public values from the three field hexes, with the guest
    /// publics beyond the commitment left zero (the real proof's shape). Each
    /// guest public is a u32 widened to a u64 and written little-endian, so
    /// the commitment's eight words land four bytes apart in eight-byte slots.
    fn make_public_values(program_vk: &str, commitment: &str, vadcop_vk: &str) -> Vec<u8> {
        let mut pv = vec![0u8; PUBLIC_VALUES_BYTES];
        pv[PROGRAM_VK_RANGE].copy_from_slice(&unhex(program_vk));
        let commitment = unhex(commitment);
        for (word, chunk) in commitment.chunks_exact(4).enumerate() {
            let at = GUEST_PUBLICS_RANGE.start + word * 8;
            pv[at..at + 4].copy_from_slice(chunk);
        }
        pv[ROOT_C_VADCOP_FINAL_RANGE].copy_from_slice(&unhex(vadcop_vk));
        pv
    }

    fn unhex(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    // Sample field values. These exercise the wire shape only; the binding
    // of a real proof to the released pins is asserted in
    // `prover/tests/real_proof_parse.rs`.
    const SAMPLE_PROGRAM_VK: &str =
        "1d16f620e2bc7e58044df7ee8d4284422a0dd37cf151cf79ecf324c131e50468";
    const SAMPLE_COMMITMENT: &str =
        "6c41981c6fd0bd9a9262fe3dcc9fe4f0d8e142651f80316a8846d6922b5214ea";
    const SAMPLE_VADCOP_VK: &str =
        "cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";

    #[test]
    fn verify_plonk_accepts_well_shaped_artifact() {
        let proof = vec![7u8; PLONK_PROOF_BYTES];
        let pv = make_public_values(SAMPLE_PROGRAM_VK, SAMPLE_COMMITMENT, SAMPLE_VADCOP_VK);
        assert_eq!(verify_plonk(&proof, &pv), Ok(()));
        assert_eq!(verify_aggregated_range(&proof, &pv), Ok(()));
    }

    #[test]
    fn verify_plonk_rejects_wrong_lengths() {
        let pv = make_public_values(SAMPLE_PROGRAM_VK, SAMPLE_COMMITMENT, SAMPLE_VADCOP_VK);
        assert_eq!(
            verify_plonk(&[0u8; 767], &pv),
            Err(VerifyError::ProofLength { got: 767 })
        );
        assert_eq!(
            verify_plonk(&[0u8; PLONK_PROOF_BYTES], &[0u8; 319]),
            Err(VerifyError::PublicValuesLength { got: 319 })
        );
    }

    #[test]
    fn verify_plonk_bound_binds_the_expected_keys() {
        let proof = vec![7u8; PLONK_PROOF_BYTES];
        let pv = make_public_values(SAMPLE_PROGRAM_VK, SAMPLE_COMMITMENT, SAMPLE_VADCOP_VK);
        let expected = ExpectedProgram {
            program_vk: unhex(SAMPLE_PROGRAM_VK),
            root_c_vadcop_final: unhex(SAMPLE_VADCOP_VK),
        };
        assert_eq!(verify_plonk_bound(&proof, &pv, &expected), Ok(()));

        // A proof under a different guest program is rejected.
        let mut wrong_program = expected;
        wrong_program.program_vk[0] ^= 0xFF;
        assert_eq!(
            verify_plonk_bound(&proof, &pv, &wrong_program),
            Err(VerifyError::ProgramVkMismatch)
        );

        // A proof under a different SNARK setup is rejected.
        let mut wrong_setup = expected;
        wrong_setup.root_c_vadcop_final[31] ^= 0x01;
        assert_eq!(
            verify_plonk_bound(&proof, &pv, &wrong_setup),
            Err(VerifyError::RootCVadcopFinalMismatch)
        );
    }

    #[test]
    fn public_signal_is_reduced_deterministic_and_bit_sensitive() {
        let pv = make_public_values(SAMPLE_PROGRAM_VK, SAMPLE_COMMITMENT, SAMPLE_VADCOP_VK);
        let signal = public_signal(&pv).unwrap();

        // Deterministic.
        assert_eq!(signal, public_signal(&pv).unwrap());

        // Reduced below the BN254 scalar-field modulus.
        assert!(
            signal < BN254_FR_MODULUS_BE,
            "public signal must be reduced mod r"
        );

        // A one-bit change in the commitment changes the signal.
        let mut pv2 = pv.clone();
        pv2[32] ^= 0x01;
        assert_ne!(signal, public_signal(&pv2).unwrap());
    }
}
