//! Pure parsing / validation / commitment logic for the ZiSK proof
//! aggregator guest.
//!
//! Everything in this library is host-testable: it depends only on `core`
//! and `alloc` plus a keccak backend (the ZiSK-accelerated
//! `alloy-primitives` native keccak inside the zkVM, `tiny-keccak` on the
//! host — same function, so host tests exercise the exact logic the guest
//! runs; the keccak over the folded range is one call, which keeps the
//! zkVM on the precompile). The zkVM binary
//! (`src/main.rs`) is a thin shell that wires these functions to `ziskos`
//! I/O and in-guest proof verification; the host-side input assembler
//! (`prover/src/aggregator_input.rs`) reuses this parser to validate the
//! streams it frames, so assembler and guest can never disagree on layout.
//!
//! # Serialized proof stream (u64 LE words)
//!
//! The unit of input is the byte stream `cargo-zisk` clients obtain from
//! `zisk_common::Proof::get_proof_bytes()` for a **non-minimal
//! `vadcop_final`** proof (ZiSK v0.18.0):
//!
//! ```text
//! [minimal(1)][n_publics=68(1)][program_vk(4)][publics(64)]
//! [proof body(41_947)][vadcop_vk(4)]
//! ```
//!
//! `publics[0..8]` carry the STF guest's batch-commitment u32 words (one
//! u32 per u64 word, packed little-endian by `ziskos::io::commit_slice`).
//! Only non-minimal proofs are accepted: the minimal/compressed variant
//! hashes with Poseidon2-8, which has no ZiSK precompile and would run the
//! permutation in software.
//!
//! # Committed output
//!
//! A single keccak digest binding both inner VKs (prover-supplied input,
//! so they MUST be committed for the proof to bind them) and the range
//! public input, in the exact forms the L1 range verifier consumes:
//!
//! ```text
//! digest = keccak256(innerProgramVK ‖ rootCVadcopFinal ‖ rangePublicInput)
//! ```
//!
//! - `innerProgramVK`: 32 bytes — the STF guest's 4 ROM-root u64 limbs,
//!   big-endian each, in order (wire public-values bytes `[0..32]`).
//! - `rootCVadcopFinal`: 32 bytes — the 4 vadcop-final VK u64 limbs,
//!   big-endian each, in order (wire public-values bytes `[288..320]`).
//! - `rangePublicInput`: 32-byte big-endian uint256 — the settlement
//!   layer's `ZKsyncOSVerifier.computeZKsyncOSHash(0, publicInputs)` over
//!   the per-batch public inputs, in batch order:
//!
//! ```text
//! folded = N == 1 ? PI_0 : keccak256(PI_0 ‖ PI_1 ‖ … ‖ PI_{N-1})
//! rangePublicInput = folded >> 32
//! ```
//!
//! Per-batch PI representation: the STF guest's full 32-byte batch
//! commitment (wire public-values bytes `[32..64]`), read as a big-endian
//! uint256. The fold consumes it untruncated; the settlement layer's
//! `PUBLIC_INPUT_SHIFT` applies once, to the folded result.
//!
//! The settlement layer rejects a non-zero carried hash, so a range
//! carries no continuation input and the guest supplies none.
//!
//! The cross-stack test vector (real 4-batch session) shared with the
//! server and L1-contract workstreams is pinned in `BINDING_VECTOR.md`
//! next to this package and asserted by `cross_stack_binding_vector`
//! below.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// Words preceding the publics in a serialized proof: `[minimal][n_publics]`.
pub const HEADER_WORDS: usize = 2;
/// u64 words in the guest-ELF ROM root (program VK).
pub const PROGRAM_VK_WORDS: usize = 4;
/// u64 words in the publics region (`zisk_verifier::ZISK_PUBLICS`).
pub const PUBLICS_WORDS: usize = 64;
/// u64 words in the vadcop-final verification key appended to the stream.
pub const VADCOP_VK_WORDS: usize = 4;
/// Publics words carrying the STF guest's batch commitment.
pub const COMMITMENT_WORDS: usize = 8;
/// Expected `n_publics` header word: program VK + publics.
pub const EXPECTED_N_PUBLICS: u64 = (PROGRAM_VK_WORDS + PUBLICS_WORDS) as u64;

/// u64 words in a non-minimal `vadcop_final` proof body under the pinned
/// pil2-proofman v0.18.0 recursive setup
/// (`proofman_verifier::expected_vadcop_final_proof_bytes() / 8`).
///
/// Part of the proof-format pin: it changes only with a
/// pil2-proofman upgrade, which rotates every VK anyway. A host test in
/// `prover/` (`vadcop_body_words_matches_pinned_verifier`) asserts this
/// constant against the real `proofman-verifier` crate at the same tag.
pub const VADCOP_FINAL_BODY_WORDS: usize = 41_947;

/// Total u64 words in a serialized non-minimal proof stream.
pub const PROOF_STREAM_WORDS: usize =
    HEADER_WORDS + PROGRAM_VK_WORDS + PUBLICS_WORDS + VADCOP_FINAL_BODY_WORDS + VADCOP_VK_WORDS;
/// Total bytes in a serialized non-minimal proof stream.
pub const PROOF_STREAM_BYTES: usize = PROOF_STREAM_WORDS * 8;

/// Bytes committed by the aggregator guest (a single keccak digest).
pub const OUTPUT_BYTES: usize = 32;

/// Validation errors. Every variant is a hard input error — the guest
/// panics on all of them (an aggregation input is assembled by our own
/// tooling; anything malformed is a bug, not an expected condition).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggError {
    /// Frame bytes are not 8-byte aligned or not a multiple of 8 long.
    Misaligned,
    /// The count frame is not exactly 8 bytes.
    BadCountFrame { len: usize },
    /// The proof count is zero (or an aggregation was finalized empty).
    NoProofs,
    /// A proof frame is not exactly [`PROOF_STREAM_WORDS`] long.
    WrongLength { words: usize },
    /// The `minimal` flag word is not 0 — minimal proofs are not accepted.
    MinimalProof { flag: u64 },
    /// The `n_publics` header word is not [`EXPECTED_N_PUBLICS`].
    BadPublicsCount { got: u64 },
    /// A proof's program VK differs from the first proof's.
    ProgramVkMismatch,
    /// A proof's vadcop VK differs from the first proof's.
    VadcopVkMismatch,
}

impl core::fmt::Display for AggError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AggError::Misaligned => write!(f, "input frame not u64-aligned"),
            AggError::BadCountFrame { len } => {
                write!(f, "count frame must be 8 bytes, got {len}")
            }
            AggError::NoProofs => write!(f, "at least one proof required"),
            AggError::WrongLength { words } => write!(
                f,
                "proof stream must be exactly {PROOF_STREAM_WORDS} words, got {words}"
            ),
            AggError::MinimalProof { flag } => {
                write!(f, "minimal proofs are not accepted (flag word {flag})")
            }
            AggError::BadPublicsCount { got } => {
                write!(f, "n_publics must be {EXPECTED_N_PUBLICS}, got {got}")
            }
            AggError::ProgramVkMismatch => write!(f, "program VK mismatch"),
            AggError::VadcopVkMismatch => write!(f, "vadcop VK mismatch"),
        }
    }
}

/// Parse the count frame (frame 0): a single u64 LE proof count, N >= 1.
pub fn parse_count_frame(bytes: &[u8]) -> Result<usize, AggError> {
    let words: [u8; 8] = bytes
        .try_into()
        .map_err(|_| AggError::BadCountFrame { len: bytes.len() })?;
    let n = u64::from_le_bytes(words) as usize;
    if n == 0 {
        return Err(AggError::NoProofs);
    }
    Ok(n)
}

/// Reinterpret frame bytes as u64 words (zero-copy).
pub fn words_from_bytes(bytes: &[u8]) -> Result<&[u64], AggError> {
    // SAFETY: any bit pattern is a valid u64; alignment and exact length
    // are enforced via the prefix/suffix emptiness check below.
    let (prefix, words, suffix) = unsafe { bytes.align_to::<u64>() };
    if !prefix.is_empty() || !suffix.is_empty() {
        return Err(AggError::Misaligned);
    }
    Ok(words)
}

/// A validated, non-minimal `vadcop_final` proof stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofFrame<'a> {
    words: &'a [u64],
}

impl<'a> ProofFrame<'a> {
    /// Validate the stream shape: exact length, non-minimal flag, publics
    /// count. Cryptographic verification is the caller's job
    /// (`ziskos::zisklib::verify_zisk_proof(frame.words())` in the guest).
    pub fn parse(words: &'a [u64]) -> Result<Self, AggError> {
        if words.len() != PROOF_STREAM_WORDS {
            return Err(AggError::WrongLength { words: words.len() });
        }
        if words[0] != 0 {
            return Err(AggError::MinimalProof { flag: words[0] });
        }
        if words[1] != EXPECTED_N_PUBLICS {
            return Err(AggError::BadPublicsCount { got: words[1] });
        }
        Ok(Self { words })
    }

    /// The full stream, exactly what `verify_zisk_proof` consumes
    /// (`[minimal][n_publics][program_vk][publics][body][vadcop_vk]`).
    pub fn words(&self) -> &'a [u64] {
        self.words
    }

    /// The inner guest's program VK (ROM root), 4 words.
    pub fn program_vk(&self) -> &'a [u64] {
        &self.words[HEADER_WORDS..HEADER_WORDS + PROGRAM_VK_WORDS]
    }

    /// The recursive-setup (vadcop-final) VK trailing the stream, 4 words.
    pub fn vadcop_vk(&self) -> &'a [u64] {
        &self.words[self.words.len() - VADCOP_VK_WORDS..]
    }

    /// The 64 publics words (each carries a u32 payload).
    pub fn publics(&self) -> &'a [u64] {
        let start = HEADER_WORDS + PROGRAM_VK_WORDS;
        &self.words[start..start + PUBLICS_WORDS]
    }

    /// The STF guest's 32-byte batch commitment: publics words 0..8, one
    /// u32 per word, packed LE exactly as the STF guest committed them
    /// (the `as u32` truncation matches `PublicValues::new_from_u64`).
    /// These bytes are also exactly wire public-values bytes `[32..64]`,
    /// which L1 reads as a big-endian uint256.
    pub fn commitment(&self) -> [u8; 32] {
        let mut out = [0u8; COMMITMENT_WORDS * 4];
        for (w, chunk) in self.publics()[..COMMITMENT_WORDS]
            .iter()
            .zip(out.chunks_exact_mut(4))
        {
            chunk.copy_from_slice(&(*w as u32).to_le_bytes());
        }
        out
    }
}

/// A 32-byte big-endian uint256 right-shifted 32 bits: every byte moves
/// down 4 positions, the top 4 bytes zero-fill. This is the settlement
/// layer's `PUBLIC_INPUT_SHIFT` truncation to 224 bits, applied once to
/// the folded range value.
pub fn shr32(word: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[4..].copy_from_slice(&word[..28]);
    out
}

/// `ZKsyncOSVerifier.computeZKsyncOSHash(0, publicInputs)`: one keccak
/// over the concatenation of the per-batch public inputs in batch order,
/// then one `PUBLIC_INPUT_SHIFT` truncation.
///
/// INVARIANT: a one-batch range performs no keccak. The settlement layer
/// takes `publicInputs[0]` verbatim and hashes only when a range holds two
/// or more batches, so a guest that hashed a one-element concatenation
/// would commit a value the settlement layer never computes, and every
/// single-batch range — the common case — would be rejected on L1.
///
/// Each public input enters the fold untruncated. The shift applies once,
/// to the folded result.
pub fn range_public_input(batch_public_inputs: &[[u8; 32]]) -> Result<[u8; 32], AggError> {
    match batch_public_inputs {
        [] => Err(AggError::NoProofs),
        [single] => Ok(shr32(single)),
        many => Ok(shr32(&keccak256(many.as_flattened()))),
    }
}

/// Accumulates the aggregation state over a sequence of parsed frames:
/// enforces that all proofs share one (program VK, vadcop VK) pair and
/// collects their batch public inputs for the settlement layer's fold.
pub struct Aggregator {
    vks: Option<([u64; PROGRAM_VK_WORDS], [u64; VADCOP_VK_WORDS])>,
    /// The per-batch public inputs in proof order, each the full 32-byte
    /// big-endian uint256 the settlement layer supplies for that batch.
    batch_public_inputs: Vec<[u8; 32]>,
}

impl Aggregator {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            vks: None,
            batch_public_inputs: Vec::new(),
        }
    }

    /// Add one frame to the aggregation. All aggregated proofs must come
    /// from one guest and one recursive setup; the shared values are bound
    /// into the committed output.
    pub fn ingest(&mut self, frame: &ProofFrame<'_>) -> Result<(), AggError> {
        match &self.vks {
            None => {
                let mut pvk = [0u64; PROGRAM_VK_WORDS];
                let mut vvk = [0u64; VADCOP_VK_WORDS];
                pvk.copy_from_slice(frame.program_vk());
                vvk.copy_from_slice(frame.vadcop_vk());
                self.vks = Some((pvk, vvk));
            }
            Some((pvk, vvk)) => {
                if frame.program_vk() != pvk {
                    return Err(AggError::ProgramVkMismatch);
                }
                if frame.vadcop_vk() != vvk {
                    return Err(AggError::VadcopVkMismatch);
                }
            }
        }
        self.batch_public_inputs.push(frame.commitment());
        Ok(())
    }

    /// The committed output:
    /// `keccak256(innerProgramVK ‖ rootCVadcopFinal ‖ rangePublicInput)` —
    /// both VKs as their 32-byte big-endian wire forms (u64 limbs
    /// big-endian, wire public-values bytes `[0..32]` and `[288..320]`),
    /// `rangePublicInput` as a 32-byte big-endian uint256. See the crate
    /// docs for the full derivation.
    pub fn finalize(self) -> Result<[u8; OUTPUT_BYTES], AggError> {
        let (program_vk, vadcop_vk) = self.vks.ok_or(AggError::NoProofs)?;
        let range = range_public_input(&self.batch_public_inputs)?;
        let mut binding = [0u8; 96];
        for (w, chunk) in program_vk.iter().zip(binding[..32].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        for (w, chunk) in vadcop_vk.iter().zip(binding[32..64].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        binding[64..].copy_from_slice(&range);
        Ok(keccak256(&binding))
    }
}

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
#[inline]
fn keccak256(data: &[u8]) -> [u8; 32] {
    alloy_primitives::keccak256(data).0
}

#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::Hasher;
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROGRAM_VK: [u64; 4] = [1, 2, 3, 4];
    const VADCOP_VK: [u64; 4] = [5, 6, 7, 8];

    /// A well-shaped synthetic stream: exact v0.18.0 sizes, non-minimal,
    /// publics words carrying `commitment` packed one u32-LE per word
    /// (the STF guest's `commit_slice` layout). The body is deterministic
    /// filler — cryptographically invalid, structurally exact.
    fn synth_stream(program_vk: [u64; 4], vadcop_vk: [u64; 4], commitment: [u8; 32]) -> Vec<u64> {
        let mut words = Vec::with_capacity(PROOF_STREAM_WORDS);
        words.push(0); // non-minimal
        words.push(EXPECTED_N_PUBLICS);
        words.extend_from_slice(&program_vk);
        let mut publics = [0u64; PUBLICS_WORDS];
        for (p, chunk) in publics.iter_mut().zip(commitment.chunks_exact(4)) {
            *p = u32::from_le_bytes(chunk.try_into().unwrap()) as u64;
        }
        words.extend_from_slice(&publics);
        words.extend((0..VADCOP_FINAL_BODY_WORDS).map(|i| (i as u64) % (1 << 31)));
        words.extend_from_slice(&vadcop_vk);
        assert_eq!(words.len(), PROOF_STREAM_WORDS);
        words
    }

    fn unhex32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The 4 u64 limbs of a VK from its 32-byte big-endian wire form.
    fn vk_words(wire: [u8; 32]) -> [u64; 4] {
        let mut words = [0u64; 4];
        for (w, chunk) in words.iter_mut().zip(wire.chunks_exact(8)) {
            *w = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        words
    }

    #[test]
    fn count_frame_roundtrip() {
        assert_eq!(parse_count_frame(&3u64.to_le_bytes()), Ok(3));
        assert_eq!(
            parse_count_frame(&[0u8; 4]),
            Err(AggError::BadCountFrame { len: 4 })
        );
        assert_eq!(
            parse_count_frame(&[0u8; 9]),
            Err(AggError::BadCountFrame { len: 9 })
        );
        assert_eq!(parse_count_frame(&0u64.to_le_bytes()), Err(AggError::NoProofs));
    }

    #[test]
    fn words_from_bytes_enforces_shape() {
        let buf = [0u64; 4];
        let bytes: &[u8] =
            unsafe { core::slice::from_raw_parts(buf.as_ptr().cast(), 32) };
        assert_eq!(words_from_bytes(bytes).unwrap().len(), 4);
        // Not a multiple of 8.
        assert_eq!(words_from_bytes(&bytes[..15]), Err(AggError::Misaligned));
        // 8-byte length but off-alignment start.
        assert_eq!(words_from_bytes(&bytes[1..9]), Err(AggError::Misaligned));
    }

    #[test]
    fn parse_accepts_well_shaped_stream() {
        let words = synth_stream(PROGRAM_VK, VADCOP_VK, [0x11u8; 32]);
        let frame = ProofFrame::parse(&words).expect("well-shaped stream parses");
        assert_eq!(frame.program_vk(), &PROGRAM_VK);
        assert_eq!(frame.vadcop_vk(), &VADCOP_VK);
        assert_eq!(frame.publics().len(), PUBLICS_WORDS);
        assert_eq!(frame.commitment(), [0x11u8; 32]);
        assert_eq!(frame.words().len(), PROOF_STREAM_WORDS);
    }

    #[test]
    fn parse_rejects_minimal_flag() {
        let mut words = synth_stream(PROGRAM_VK, VADCOP_VK, [1u8; 32]);
        words[0] = 1;
        assert_eq!(
            ProofFrame::parse(&words),
            Err(AggError::MinimalProof { flag: 1 })
        );
    }

    #[test]
    fn parse_rejects_bad_publics_count() {
        let mut words = synth_stream(PROGRAM_VK, VADCOP_VK, [1u8; 32]);
        words[1] = 67;
        assert_eq!(
            ProofFrame::parse(&words),
            Err(AggError::BadPublicsCount { got: 67 })
        );
    }

    #[test]
    fn parse_rejects_wrong_lengths() {
        let words = synth_stream(PROGRAM_VK, VADCOP_VK, [1u8; 32]);
        // Truncated frame (e.g. a minimal-size or cut-off stream).
        assert_eq!(
            ProofFrame::parse(&words[..PROOF_STREAM_WORDS - 1]),
            Err(AggError::WrongLength {
                words: PROOF_STREAM_WORDS - 1
            })
        );
        // Over-long frame (trailing garbage would shift the vadcop VK).
        let mut long = words.clone();
        long.push(0);
        assert_eq!(
            ProofFrame::parse(&long),
            Err(AggError::WrongLength {
                words: PROOF_STREAM_WORDS + 1
            })
        );
        // Degenerate short frames.
        assert_eq!(
            ProofFrame::parse(&[0u64; 2]),
            Err(AggError::WrongLength { words: 2 })
        );
    }

    #[test]
    fn commitment_truncates_words_to_u32() {
        // Publics words are u32 payloads by construction; anything in the
        // high half must be ignored exactly like PublicValues::new_from_u64.
        let mut words = synth_stream(PROGRAM_VK, VADCOP_VK, [0x22u8; 32]);
        words[HEADER_WORDS + PROGRAM_VK_WORDS] = 0xDEAD_BEEF_2222_2222;
        let frame = ProofFrame::parse(&words).unwrap();
        assert_eq!(frame.commitment(), [0x22u8; 32]);
    }

    #[test]
    fn aggregator_rejects_vk_mismatches() {
        let a = synth_stream(PROGRAM_VK, VADCOP_VK, [1u8; 32]);
        let b = synth_stream([9, 9, 9, 9], VADCOP_VK, [2u8; 32]);
        let c = synth_stream(PROGRAM_VK, [9, 9, 9, 9], [3u8; 32]);

        let mut agg = Aggregator::new();
        agg.ingest(&ProofFrame::parse(&a).unwrap()).unwrap();
        assert_eq!(
            agg.ingest(&ProofFrame::parse(&b).unwrap()),
            Err(AggError::ProgramVkMismatch)
        );
        assert_eq!(
            agg.ingest(&ProofFrame::parse(&c).unwrap()),
            Err(AggError::VadcopVkMismatch)
        );
    }

    #[test]
    fn empty_aggregation_cannot_finalize() {
        assert_eq!(Aggregator::new().finalize(), Err(AggError::NoProofs));
    }

    #[test]
    fn shr32_moves_bytes_down_and_zero_fills() {
        let mut word = [0u8; 32];
        for (i, b) in word.iter_mut().enumerate() {
            *b = i as u8 + 1; // 0x01..=0x20
        }
        let shifted = shr32(&word);
        assert_eq!(shifted[..4], [0u8; 4], "top 4 bytes zero-fill");
        assert_eq!(shifted[4..], word[..28], "low 4 bytes dropped");
    }

    #[test]
    fn range_public_input_of_two_or_more_batches_hashes_the_concatenation() {
        let inputs = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]];
        for n in [2usize, 3] {
            let mut preimage = Vec::new();
            for pi in &inputs[..n] {
                preimage.extend_from_slice(pi);
            }
            let full = keccak256(&preimage);
            let folded = range_public_input(&inputs[..n]).unwrap();
            assert_eq!(folded[..4], [0u8; 4], "top 4 bytes zero-fill at N={n}");
            assert_eq!(folded[4..], full[..28], "one shift at the end, N={n}");
        }
    }

    /// The concatenation carries every input byte, so two ranges that
    /// differ only in the low 4 bytes of a commitment fold to different
    /// values. Truncating each input before the fold would erase exactly
    /// those bytes and collapse the two ranges onto one digest.
    #[test]
    fn range_fold_consumes_untruncated_public_inputs() {
        let mut tail_changed = [0x77u8; 32];
        tail_changed[28..].copy_from_slice(&[0xFF; 4]);
        let left = [[0x66u8; 32], [0x77u8; 32]];
        let right = [[0x66u8; 32], tail_changed];
        assert_eq!(shr32(&left[1]), shr32(&right[1]), "truncation erases them");
        assert_ne!(
            range_public_input(&left).unwrap(),
            range_public_input(&right).unwrap()
        );
    }

    #[test]
    fn empty_range_has_no_public_input() {
        assert_eq!(range_public_input(&[]), Err(AggError::NoProofs));
    }

    /// The binding digest recomputed from the specification text,
    /// independent of the Aggregator internals: one keccak over the
    /// concatenated per-batch public inputs (none for a single batch),
    /// then one truncation.
    fn reference_digest(
        program_vk: [u64; 4],
        vadcop_vk: [u64; 4],
        commitments: &[[u8; 32]],
    ) -> [u8; 32] {
        let truncate = |w: &[u8; 32]| {
            let mut out = [0u8; 32];
            out[4..].copy_from_slice(&w[..28]);
            out
        };
        let result = if commitments.len() == 1 {
            truncate(&commitments[0])
        } else {
            truncate(&keccak256(&commitments.concat()))
        };
        let mut binding = [0u8; 96];
        for (w, chunk) in program_vk.iter().zip(binding[..32].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        for (w, chunk) in vadcop_vk.iter().zip(binding[32..64].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        binding[64..].copy_from_slice(&result);
        keccak256(&binding)
    }

    #[test]
    fn binding_digest_matches_reference() {
        let streams = [
            synth_stream(PROGRAM_VK, VADCOP_VK, [0x11u8; 32]),
            synth_stream(PROGRAM_VK, VADCOP_VK, [0x22u8; 32]),
            synth_stream(PROGRAM_VK, VADCOP_VK, [0x33u8; 32]),
        ];
        let mut agg = Aggregator::new();
        for s in &streams {
            agg.ingest(&ProofFrame::parse(s).unwrap()).unwrap();
        }
        let digest = agg.finalize().unwrap();
        assert_eq!(
            digest,
            reference_digest(
                PROGRAM_VK,
                VADCOP_VK,
                &[[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]]
            )
        );
    }

    /// Range-size pins for `ZKsyncOSVerifier.computeZKsyncOSHash`, over a
    /// fixed commitment set of this test's own. The cross-stack vector
    /// below rotates with every proving session, so the size coverage
    /// stands on values that no session rotation can move.
    ///
    /// Every expected value is derived from the settlement-layer formula
    /// (`keccak256(abi.encodePacked(publicInputs)) >> 32`, with the
    /// one-batch range taking `publicInputs[0]` verbatim) outside this
    /// code base. N == 1 and N >= 2 take different branches of that
    /// formula, so only a size sweep pins both.
    #[test]
    fn range_sizes_match_the_settlement_formula() {
        const COMMITMENTS: [[u8; 32]; 4] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
        const RANGE_PUBLIC_INPUTS: [(usize, &str); 3] = [
            (
                1,
                "0000000011111111111111111111111111111111111111111111111111111111",
            ),
            (
                2,
                "000000003e92e0db88d6afea9edc4eedf62fffa4d92bcdfc310dccbe943747fe",
            ),
            (
                4,
                "0000000072710f6499c8928f4ac3fa4df9309244e2ecdf204c9e6952b435fb21",
            ),
        ];
        const DIGESTS: [&str; 3] = [
            "7cc66497f90d6cceacbac9c5c4bed4a6664195bd55c930ec13cec08a01e1a968",
            "93b7d98e4aaf5530f476557991b7ea64e6f39b57cf49b357770d275215e4cfe6",
            "2a27b63360933a134afd57eb558dbff6bd90359b1e85a7b245a8cdbe4041e62d",
        ];

        for (&(n, expected_range), expected_digest) in RANGE_PUBLIC_INPUTS.iter().zip(DIGESTS) {
            assert_eq!(
                hex(&range_public_input(&COMMITMENTS[..n]).unwrap()),
                expected_range,
                "range public input at N={n}"
            );

            let mut agg = Aggregator::new();
            for commitment in &COMMITMENTS[..n] {
                let words = synth_stream(PROGRAM_VK, VADCOP_VK, *commitment);
                agg.ingest(&ProofFrame::parse(&words).unwrap()).unwrap();
            }
            assert_eq!(
                hex(&agg.finalize().unwrap()),
                expected_digest,
                "binding digest at N={n}"
            );
        }
    }

    /// THE cross-stack binding vector, computed from the real 4-batch
    /// aggregation session (ZiSK v0.18.0). `BINDING_VECTOR.md` next to
    /// this package records the same values; the server and L1-contract
    /// workstreams pin them verbatim. Update all of them together — they
    /// must never diverge.
    #[test]
    fn cross_stack_binding_vector() {
        const INNER_PROGRAM_VK: &str =
            "8168c5d383a50a9c7a40561b82bf679cc6dfdab0308417b4fea653362d78d080";
        const ROOT_C_VADCOP_FINAL: &str =
            "cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";
        const COMMITMENTS: [&str; 4] = [
            "63c7606faee0ee9eff230fec391e64c0c82a0277947973ce7f6f1c9088c821dd",
            "7d6a5ed6ffda210164c11dd6f6fccbd35c4ff70632e845a5bf256e3ec48940b9",
            "d5a7b4485d1aece18348655132e73c86b23fa0f251adb173f80123d05a914f15",
            "c5ed165443011bac65df4d0f4240de3429c033996e9fce630a631e117537cd61",
        ];
        const RANGE_PUBLIC_INPUT: &str =
            "00000000108311cf154dafcd8fbeb3d29ff924941d60db59f523d33baa5d2ca5";
        const DIGEST: &str =
            "f29341c341f2622ba86a21bbb36dde9742e1983e531c278fd1cee04c6f823e2c";

        let program_vk = vk_words(unhex32(INNER_PROGRAM_VK));
        let vadcop_vk = vk_words(unhex32(ROOT_C_VADCOP_FINAL));
        let streams: Vec<Vec<u64>> = COMMITMENTS
            .iter()
            .map(|c| synth_stream(program_vk, vadcop_vk, unhex32(c)))
            .collect();

        // The range public input, via the public helpers.
        let pis: Vec<[u8; 32]> = streams
            .iter()
            .map(|s| ProofFrame::parse(s).unwrap().commitment())
            .collect();
        assert_eq!(
            hex(&range_public_input(&pis).unwrap()),
            RANGE_PUBLIC_INPUT,
            "rangePublicInput"
        );

        // Final digest, via the Aggregator (the code path the guest runs).
        let mut agg = Aggregator::new();
        for s in &streams {
            agg.ingest(&ProofFrame::parse(s).unwrap()).unwrap();
        }
        let digest = agg.finalize().unwrap();
        assert_eq!(hex(&digest), DIGEST, "binding digest");
    }
}
