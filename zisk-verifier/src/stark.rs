//! Native (pure-Rust) verification of the intermediate `vadcop_final` STARK
//! proof, via pil2-proofman's `proofman-verifier` (feature `stark-native`).
//!
//! This is the one cryptographic verification the pinned ZiSK toolchain exposes
//! natively and dependency-light. It verifies the STARK layer, NOT the final
//! BN254 PLONK wrap (which the toolchain checks only through the external
//! `snarkjs` CLI — see the crate docs).
//!
//! The unit of input is the serialized non-minimal `vadcop_final` stream, the
//! exact byte layout `cargo-zisk` clients obtain from `Proof::get_proof_bytes()`
//! and the aggregator guest verifies in-zkVM:
//!
//! ```text
//! [minimal(1)][n_publics=68(1)][program_vk(4)][publics(64)][body][vadcop_vk(4)]
//! ```
//!
//! The prover holds these streams for the aggregated lane before it aggregates
//! them (see `prover/src/prover.rs::generate_vadcop_proof`), so this checks a
//! per-batch STARK proof off-chain before the aggregator wraps the range.

use zksync_os_zisk_guest_aggregator as agg;

use crate::VerifyError;

/// Verify a serialized non-minimal `vadcop_final` STARK proof stream.
///
/// The stream is parsed with the aggregator guest's own parser (shape, the
/// non-minimal flag, the publics count), then verified cryptographically with
/// `proofman-verifier` at the pinned v0.18.0 recursive setup. Returns `Ok(())`
/// only when the STARK proof verifies against the vadcop-final VK the stream
/// carries.
pub fn verify_vadcop_final_stream(stream: &[u8]) -> Result<(), VerifyError> {
    let words =
        agg::words_from_bytes(stream).map_err(|e| VerifyError::StreamMalformed(e.to_string()))?;
    let frame =
        agg::ProofFrame::parse(words).map_err(|e| VerifyError::StreamMalformed(e.to_string()))?;

    // proofman's `verify_vadcop_final_u64` consumes the `proof_with_publics`
    // slice `[n_publics][program_vk ‖ publics][body]` and the vadcop-final VK
    // separately. In the stream that is every word except the leading `minimal`
    // flag and the trailing VK. See `zisk_common::Proof::verify` (Vadcop path).
    let all = frame.words();
    let proof_with_publics = &all[1..all.len() - agg::VADCOP_VK_WORDS];
    let vk = frame.vadcop_vk();

    if proofman_verifier::verify_vadcop_final_u64(proof_with_publics, vk) {
        Ok(())
    } else {
        Err(VerifyError::StarkInvalid)
    }
}

/// Verify a `cargo-zisk prove` output file that carries a `vadcop_final` proof
/// (a run WITHOUT `--plonk`). This decodes the on-disk proof file into a stream
/// and verifies it with [`verify_vadcop_final_stream`].
///
/// The prover writes these files; this reads them back and checks them without
/// the daemon. The decode mirrors `zisk_common::Proof` (bincode 2, standard
/// config) for the Vadcop body only.
pub fn verify_vadcop_final_proof_file(bytes: &[u8]) -> Result<(), VerifyError> {
    let stream = proof_file::stream_from_proof_file(bytes)?;
    verify_vadcop_final_stream(&stream)
}

/// Decode a `cargo-zisk` Vadcop-body proof file into a serialized stream.
mod proof_file {
    use super::agg;
    use crate::VerifyError;

    // Do not depend on bincode/serde in the crate's own dependency set; decode
    // the proof file lazily only when this entry point runs, using the crate's
    // dev-visible bincode in tests and the caller's otherwise. To keep the base
    // crate lean, this decoder is implemented against a minimal hand-rolled
    // bincode-2 standard reader for the exact Vadcop shape.
    //
    // Layout (bincode 2 standard, little-endian, varint lengths):
    //   enum ProofBody discriminant (varint u32): 0 = Vadcop
    //     Vadcop { proof: Vec<u64>, zisk_vk: Vec<u64>, minimal: bool }
    //   publics: { data: Vec<u8> }
    //   program_vk: { vk: Vec<u64> }

    const PROGRAM_VK_WORDS: usize = 4;

    struct Reader<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl<'a> Reader<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, pos: 0 }
        }

        fn byte(&mut self) -> Result<u8, VerifyError> {
            let b = *self
                .bytes
                .get(self.pos)
                .ok_or_else(|| VerifyError::StreamMalformed("proof file truncated".into()))?;
            self.pos += 1;
            Ok(b)
        }

        /// bincode 2 standard varint for lengths and unsigned integers: a lead
        /// byte < 251 is the value; 251/252/253 prefix a u16/u32/u64 (LE).
        fn varint(&mut self) -> Result<u64, VerifyError> {
            let lead = self.byte()?;
            match lead {
                0..=250 => Ok(lead as u64),
                251 => {
                    let mut b = [0u8; 2];
                    b.copy_from_slice(self.take(2)?);
                    Ok(u16::from_le_bytes(b) as u64)
                }
                252 => {
                    let mut b = [0u8; 4];
                    b.copy_from_slice(self.take(4)?);
                    Ok(u32::from_le_bytes(b) as u64)
                }
                253 => {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(self.take(8)?);
                    Ok(u64::from_le_bytes(b))
                }
                _ => Err(VerifyError::StreamMalformed(
                    "unsupported varint width (u128)".into(),
                )),
            }
        }

        fn take(&mut self, n: usize) -> Result<&'a [u8], VerifyError> {
            let end = self
                .pos
                .checked_add(n)
                .filter(|e| *e <= self.bytes.len())
                .ok_or_else(|| VerifyError::StreamMalformed("proof file truncated".into()))?;
            let slice = &self.bytes[self.pos..end];
            self.pos = end;
            Ok(slice)
        }

        fn u64_vec(&mut self) -> Result<Vec<u64>, VerifyError> {
            let len = self.varint()? as usize;
            let mut out = Vec::with_capacity(len.min(1 << 20));
            for _ in 0..len {
                out.push(self.varint()?);
            }
            Ok(out)
        }
    }

    pub(super) fn stream_from_proof_file(bytes: &[u8]) -> Result<Vec<u8>, VerifyError> {
        let mut r = Reader::new(bytes);

        let discriminant = r.varint()?;
        if discriminant != 0 {
            return Err(VerifyError::StreamMalformed(
                "proof file is not a Vadcop body (run cargo-zisk prove WITHOUT --plonk)".into(),
            ));
        }
        let body = r.u64_vec()?;
        let zisk_vk = r.u64_vec()?;
        let minimal = r.byte()? != 0;
        if minimal {
            return Err(VerifyError::StreamMalformed(
                "minimal vadcop_final proofs are not accepted".into(),
            ));
        }

        // publics: Vec<u8> (256 bytes).
        let publics_len = r.varint()? as usize;
        let publics_data = r.take(publics_len)?.to_vec();

        // program_vk: Vec<u64> (4 words).
        let program_vk = r.u64_vec()?;

        if program_vk.len() != PROGRAM_VK_WORDS || zisk_vk.len() != PROGRAM_VK_WORDS {
            return Err(VerifyError::StreamMalformed(format!(
                "VK word count: program {} vadcop {}",
                program_vk.len(),
                zisk_vk.len()
            )));
        }
        if publics_data.len() != agg::PUBLICS_WORDS * 4 {
            return Err(VerifyError::StreamMalformed(format!(
                "publics region {} bytes, expected {}",
                publics_data.len(),
                agg::PUBLICS_WORDS * 4
            )));
        }
        if body.len() != agg::VADCOP_FINAL_BODY_WORDS {
            return Err(VerifyError::StreamMalformed(format!(
                "vadcop_final body {} words, expected {}",
                body.len(),
                agg::VADCOP_FINAL_BODY_WORDS
            )));
        }

        // Reassemble the get_proof_bytes() stream.
        let mut words: Vec<u64> = Vec::with_capacity(agg::PROOF_STREAM_WORDS);
        words.push(0); // non-minimal
        words.push((PROGRAM_VK_WORDS + agg::PUBLICS_WORDS) as u64);
        words.extend_from_slice(&program_vk);
        words.extend(
            publics_data
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c) as u64),
        );
        words.extend_from_slice(&body);
        words.extend_from_slice(&zisk_vk);

        let mut out = Vec::with_capacity(words.len() * 8);
        for w in &words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_short_stream() {
        let err = verify_vadcop_final_stream(&[0u8; 16]).unwrap_err();
        assert!(
            matches!(err, VerifyError::StreamMalformed(_)),
            "unexpected error: {err}"
        );
    }

    /// The committed real v0.18.0 `vadcop_final` proof file (batch 1 of the
    /// binding-vector range) must verify natively. This is a full STARK
    /// verification, no external tooling.
    #[test]
    fn verifies_the_real_vadcop_final_proof_file() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../prover/tests/data/real_vadcop_final_zisk_v0.18.0.bin"
        );
        let bytes = std::fs::read(path).expect("read committed vadcop_final fixture");
        assert_eq!(verify_vadcop_final_proof_file(&bytes), Ok(()));
    }
}
