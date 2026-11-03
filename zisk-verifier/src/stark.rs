//! Native (pure-Rust) verification of the intermediate `vadcop_final` STARK
//! proof, via ZiSK's `zisk-verifier` crate (feature `stark-native`): the same
//! generated verifier `ziskos::zisklib::verify_zisk_proof` runs in the
//! aggregator guest.
//!
//! This is the one cryptographic verification the pinned ZiSK toolchain exposes
//! natively and dependency-light. It verifies the STARK layer, NOT the final
//! BN254 pilfflonk wrap (which the toolchain checks only through pilfflonk's
//! JavaScript verifier — see the crate docs).
//!
//! The unit of input is the serialized non-minimal `vadcop_final` stream, the
//! exact byte layout `cargo-zisk` clients obtain from `Proof::get_proof_bytes()`
//! and the aggregator guest verifies in-zkVM:
//!
//! ```text
//! [minimal(1)][n_publics=69(1)][is_vadcop_final_proof(1)][program_vk(4)]
//! [publics(64)][body][vadcop_vk(4)][hash_tag(1)]
//! ```
//!
//! The prover holds these streams for the aggregated lane before it aggregates
//! them (see `prover/src/prover.rs::generate_vadcop_proof`), so this checks a
//! per-batch STARK proof off-chain before the aggregator wraps the range.
//!
//! The proof is verified under this release's vadcop-final key, never under the
//! key the stream carries: a proof checked against the key it ships with proves
//! nothing, so the carried key is only compared with the trusted one.

use zksync_os_zisk_guest_aggregator as agg;

use crate::VerifyError;

/// The vadcop-final key of ZiSK's released Poseidon1 setup, the key every
/// per-batch proof of this lane verifies under. The aggregator's
/// `ROOT_C_VADCOP_FINAL` pin is the same key (asserted in the tests below).
const TRUSTED_VADCOP_VK: [u64; agg::VADCOP_VK_WORDS] =
    zisk_verifier_upstream::VADCOP_FINAL_VK_POSEIDON1;

/// Verify a serialized non-minimal `vadcop_final` STARK proof stream.
///
/// The stream is parsed with the aggregator guest's own parser (shape, the
/// non-minimal flag, the publics count, the hash tag, the leaf flag), then
/// verified cryptographically with ZiSK's `zisk-verifier` under
/// [`TRUSTED_VADCOP_VK`]. Returns `Ok(())` only when the STARK proof verifies
/// under that key.
pub fn verify_vadcop_final_stream(stream: &[u8]) -> Result<(), VerifyError> {
    let words =
        agg::words_from_bytes(stream).map_err(|e| VerifyError::StreamMalformed(e.to_string()))?;
    let frame =
        agg::ProofFrame::parse(words).map_err(|e| VerifyError::StreamMalformed(e.to_string()))?;

    // A stream from another setup would fail the STARK check below anyway;
    // naming the key here tells the operator why.
    if frame.vadcop_vk() != TRUSTED_VADCOP_VK {
        return Err(VerifyError::StreamMalformed(format!(
            "vadcop-final key {:?} is not the release key {:?}",
            frame.vadcop_vk(),
            TRUSTED_VADCOP_VK
        )));
    }

    match zisk_verifier_upstream::verify_saved_words(frame.words(), &TRUSTED_VADCOP_VK, None) {
        Ok(_) => Ok(()),
        Err(zisk_verifier_upstream::VerifyError::InvalidProof) => Err(VerifyError::StarkInvalid),
        Err(e) => Err(VerifyError::StreamMalformed(e.to_string())),
    }
}

/// Verify a `cargo-zisk prove` output file that carries a `vadcop_final` proof
/// (a run WITHOUT a final SNARK). This takes the stream out of the file and
/// verifies it with [`verify_vadcop_final_stream`].
pub fn verify_vadcop_final_proof_file(bytes: &[u8]) -> Result<(), VerifyError> {
    verify_vadcop_final_stream(stream_from_proof_file(bytes)?)
}

/// The stream inside a `cargo-zisk prove` `vadcop_final` file. Since ZiSK
/// 1.4.0 the file is the stream itself, followed by a seed trailer
/// `[seed(4)][b"ZISKSEED"]` when the proof carries the execution's random
/// seed. The guest verifier refuses the trailer, so it is cut off here.
fn stream_from_proof_file(bytes: &[u8]) -> Result<&[u8], VerifyError> {
    const TRAILER_BYTES: usize = (zisk_verifier_upstream::SEED_LEN_WORDS + 1) * 8;

    if !bytes.len().is_multiple_of(8) {
        return Err(VerifyError::StreamMalformed(format!(
            "proof file is {} bytes, not a whole number of u64 words",
            bytes.len()
        )));
    }
    let tag = zisk_verifier_upstream::SEED_TRAILER_TAG.to_le_bytes();
    if bytes.len() >= TRAILER_BYTES && bytes.ends_with(&tag) {
        Ok(&bytes[..bytes.len() - TRAILER_BYTES])
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hash family of this lane's proving key; the parser pins its wire
    /// tag (`agg::EXPECTED_HASH_TAG`).
    const HASH_FAMILY: &str = "Poseidon1";

    #[test]
    fn rejects_a_short_stream() {
        let err = verify_vadcop_final_stream(&[0u8; 16]).unwrap_err();
        assert!(
            matches!(err, VerifyError::StreamMalformed(_)),
            "unexpected error: {err}"
        );
    }

    /// The parser's pinned tag is this family's wire tag in ZiSK's verifier
    /// crate, so the stream the daemon assembles is the one the guest verifies.
    #[test]
    fn pinned_hash_tag_is_the_upstream_tag() {
        assert_eq!(
            zisk_verifier_upstream::hash_tag(HASH_FAMILY),
            Some(agg::EXPECTED_HASH_TAG)
        );
    }

    /// The parser's pinned body size is the size ZiSK's verifier expects for a
    /// non-minimal proof of this family.
    #[test]
    fn pinned_body_size_is_the_upstream_size() {
        let stream_bytes = agg::PROOF_STREAM_BYTES;
        let tail_bytes = (agg::VADCOP_VK_WORDS + agg::HASH_TAG_WORDS) * 8;
        let header_bytes = (agg::HEADER_WORDS + agg::EXPECTED_N_PUBLICS as usize) * 8;
        assert_eq!(
            zisk_verifier_upstream::proof_size(HASH_FAMILY, false),
            Some(zisk_verifier_upstream::ProofSize::Exact(
                stream_bytes - header_bytes - tail_bytes
            ))
        );
    }

    /// The release key this crate verifies under is the vadcop-final root the
    /// aggregator lane pins (`guest-aggregator/ROOT_C_VADCOP_FINAL`, the four
    /// limbs big-endian).
    #[test]
    fn trusted_key_is_the_root_c_pin() {
        let record = include_str!("../../guest-aggregator/ROOT_C_VADCOP_FINAL");
        let pin = record
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("0x"))
            .expect("ROOT_C_VADCOP_FINAL has a 0x value line");
        let mut limbs = [0u64; agg::VADCOP_VK_WORDS];
        for (i, limb) in limbs.iter_mut().enumerate() {
            *limb = u64::from_str_radix(&pin[2 + 16 * i..2 + 16 * (i + 1)], 16).unwrap();
        }
        assert_eq!(limbs, TRUSTED_VADCOP_VK);
    }

    #[test]
    fn strips_the_seed_trailer() {
        let mut file = vec![1u8; 24];
        file.extend_from_slice(&[2u8; 32]);
        file.extend_from_slice(&zisk_verifier_upstream::SEED_TRAILER_TAG.to_le_bytes());
        assert_eq!(stream_from_proof_file(&file).unwrap(), &[1u8; 24][..]);
        assert_eq!(stream_from_proof_file(&[1u8; 24]).unwrap(), &[1u8; 24][..]);
        assert!(stream_from_proof_file(&[1u8; 23]).is_err());
    }

    /// The committed real `vadcop_final` proof file (batch 1 of the
    /// binding-vector range) must verify natively. This is a full STARK
    /// verification, no external tooling.
    #[test]
    fn verifies_the_real_vadcop_final_proof_file() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../prover/tests/data/real_vadcop_final_zisk_v1.4.0-alpha.bin"
        );
        let bytes = std::fs::read(path).expect("read committed vadcop_final fixture");
        assert_eq!(verify_vadcop_final_proof_file(&bytes), Ok(()));
    }
}
