//! Pure parsing / validation / commitment logic for the ZiSK proof
//! aggregator guest.
//!
//! Everything in this library is host-testable: it depends only on `core`
//! plus a keccak backend (the ZiSK-accelerated `alloy-primitives` native
//! keccak inside the zkVM, `tiny-keccak` on the host — same function, so
//! host tests exercise the exact logic the guest runs). The zkVM binary
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
//! so they MUST be committed for the proof to bind them) and the chained
//! per-batch public inputs, in the exact forms the L1 `MultiProofVerifier`
//! consumes:
//!
//! ```text
//! digest = keccak256(innerProgramVK ‖ rootCVadcopFinal ‖ chainedPI)
//! ```
//!
//! - `innerProgramVK`: 32 bytes — the STF guest's 4 ROM-root u64 limbs,
//!   big-endian each, in order (wire public-values bytes `[0..32]`).
//! - `rootCVadcopFinal`: 32 bytes — the 4 vadcop-final VK u64 limbs,
//!   big-endian each, in order (wire public-values bytes `[288..320]`).
//! - `chainedPI`: 32-byte big-endian uint256 — the contract's
//!   `MultiProofVerifier._computeZKsyncOSHash(0, publicInputs)` replayed
//!   over the per-batch public inputs, in proof order:
//!
//! ```text
//! result = PI_0                                       // initialHash == 0
//! for i in 1..N:
//!     result = keccak256(be32(result) ‖ be32(PI_i)) >> 32
//! chainedPI = result
//! ```
//!
//! Per-batch PI representation — established by the contract's
//! single-batch binding check (`ziskCommitment >> 32 == publicInput`,
//! where `ziskCommitment` is wire public-values bytes `[32..64]` read as
//! a big-endian uint256): the full 32-byte batch commitment interpreted
//! big-endian and right-shifted 32 bits. Every value in the chain is
//! 224-bit (the Executor's `PUBLIC_INPUT_SHIFT` truncation), carried as a
//! 32-byte big-endian word whose top 4 bytes are zero.
//!
//! The cross-stack test vector (real 4-batch session) shared with the
//! server and L1-contract workstreams is pinned in `BINDING_VECTOR.md`
//! next to this package and asserted by `cross_stack_binding_vector`
//! below.

#![cfg_attr(not(test), no_std)]

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

    /// The per-batch public input as the L1 contract consumes it.
    ///
    /// `MultiProofVerifier`'s single-batch binding check is
    /// `ziskCommitment >> 32 == publicInput`, with `ziskCommitment` the
    /// full 32-byte commitment read as a big-endian uint256. The public
    /// input is therefore the commitment's top 28 bytes right-aligned in
    /// 32: a 224-bit value that drops the commitment's last 4 bytes and
    /// zeroes the first 4.
    pub fn commitment_public_input(&self) -> [u8; 32] {
        shr32(&self.commitment())
    }
}

/// A 32-byte big-endian uint256 right-shifted 32 bits: every byte moves
/// down 4 positions, the top 4 bytes zero-fill. This is the contracts'
/// `PUBLIC_INPUT_SHIFT` truncation to 224 bits, applied both to per-batch
/// public inputs and to every `_computeZKsyncOSHash` chain step.
pub fn shr32(word: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[4..].copy_from_slice(&word[..28]);
    out
}

/// One step of `MultiProofVerifier._computeZKsyncOSHash`:
/// `uint256(keccak256(abi.encodePacked(acc, pi))) >> 32`, both operands
/// 32-byte big-endian uint256 words.
pub fn chain_step(acc: &[u8; 32], pi: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(acc);
    preimage[32..].copy_from_slice(pi);
    shr32(&keccak256(&preimage))
}

/// Accumulates the aggregation state over a sequence of parsed frames:
/// enforces that all proofs share one (program VK, vadcop VK) pair and
/// chains their batch public inputs exactly like the L1 contract's
/// `MultiProofVerifier._computeZKsyncOSHash` with `initialHash = 0`.
pub struct Aggregator {
    vks: Option<([u64; PROGRAM_VK_WORDS], [u64; VADCOP_VK_WORDS])>,
    /// `_computeZKsyncOSHash` accumulator, a 32-byte big-endian uint256.
    /// Meaningful only once `vks` is set; the first ingested proof seeds
    /// it with its public input (the contract's `initialHash == 0` rule:
    /// the first PI enters the chain unhashed).
    chained: [u8; 32],
}

impl Aggregator {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            vks: None,
            chained: [0u8; 32],
        }
    }

    /// Fold one frame in. All aggregated proofs must come from one guest
    /// and one recursive setup; the shared values are bound into the
    /// committed output.
    pub fn ingest(&mut self, frame: &ProofFrame<'_>) -> Result<(), AggError> {
        let pi = frame.commitment_public_input();
        match &self.vks {
            None => {
                let mut pvk = [0u64; PROGRAM_VK_WORDS];
                let mut vvk = [0u64; VADCOP_VK_WORDS];
                pvk.copy_from_slice(frame.program_vk());
                vvk.copy_from_slice(frame.vadcop_vk());
                self.vks = Some((pvk, vvk));
                self.chained = pi;
            }
            Some((pvk, vvk)) => {
                if frame.program_vk() != pvk {
                    return Err(AggError::ProgramVkMismatch);
                }
                if frame.vadcop_vk() != vvk {
                    return Err(AggError::VadcopVkMismatch);
                }
                self.chained = chain_step(&self.chained, &pi);
            }
        }
        Ok(())
    }

    /// The committed output:
    /// `keccak256(innerProgramVK ‖ rootCVadcopFinal ‖ chainedPI)` — both
    /// VKs as their 32-byte big-endian wire forms (u64 limbs big-endian,
    /// wire public-values bytes `[0..32]` and `[288..320]`), `chainedPI`
    /// as a 32-byte big-endian uint256. See the crate docs for the full
    /// derivation.
    pub fn finalize(self) -> Result<[u8; OUTPUT_BYTES], AggError> {
        let (program_vk, vadcop_vk) = self.vks.ok_or(AggError::NoProofs)?;
        let mut binding = [0u8; 96];
        for (w, chunk) in program_vk.iter().zip(binding[..32].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        for (w, chunk) in vadcop_vk.iter().zip(binding[32..64].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        binding[64..].copy_from_slice(&self.chained);
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
    fn public_input_is_commitment_shifted_right_32_bits() {
        let mut commitment = [0u8; 32];
        for (i, b) in commitment.iter_mut().enumerate() {
            *b = 0xA0 + i as u8;
        }
        let words = synth_stream(PROGRAM_VK, VADCOP_VK, commitment);
        let frame = ProofFrame::parse(&words).unwrap();
        assert_eq!(frame.commitment(), commitment);
        assert_eq!(frame.commitment_public_input(), shr32(&commitment));
    }

    #[test]
    fn chain_step_hashes_then_truncates() {
        let acc = [0xAAu8; 32];
        let pi = [0xBBu8; 32];
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&acc);
        preimage[32..].copy_from_slice(&pi);
        let full = keccak256(&preimage);
        let step = chain_step(&acc, &pi);
        assert_eq!(step[..4], [0u8; 4]);
        assert_eq!(step[4..], full[..28]);
    }

    /// The binding digest recomputed step by step, independent of the
    /// Aggregator internals: seed with the first public input (the
    /// contract's `initialHash == 0` rule), then
    /// `keccak256(acc ‖ pi) >> 32` per remaining input.
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
        let mut result = truncate(&commitments[0]);
        for c in &commitments[1..] {
            let mut preimage = [0u8; 64];
            preimage[..32].copy_from_slice(&result);
            preimage[32..].copy_from_slice(&truncate(c));
            result = truncate(&keccak256(&preimage));
        }
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

    /// A single proof's chain value is its public input verbatim — the
    /// contract's `initialHash == 0` branch consumes `publicInputs[0]`
    /// without hashing it. This is exactly the N==1 on-chain check
    /// (`ziskCommitment >> 32 == publicInput`), so the single-proof digest
    /// must bind the raw truncated commitment, never `chain_step` from a
    /// zero accumulator.
    #[test]
    fn single_proof_seeds_chain_without_hashing() {
        let commitment = [0x5Au8; 32];
        let words = synth_stream(PROGRAM_VK, VADCOP_VK, commitment);
        let frame = ProofFrame::parse(&words).unwrap();

        let mut agg = Aggregator::new();
        agg.ingest(&frame).unwrap();
        let digest = agg.finalize().unwrap();

        let mut binding = [0u8; 96];
        for (w, chunk) in PROGRAM_VK.iter().zip(binding[..32].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        for (w, chunk) in VADCOP_VK.iter().zip(binding[32..64].chunks_exact_mut(8)) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        binding[64..].copy_from_slice(&shr32(&commitment));
        assert_eq!(digest, keccak256(&binding));

        // The seed rule is observable: hashing the first PI from a zero
        // accumulator gives a different chain value.
        assert_ne!(shr32(&commitment), chain_step(&[0u8; 32], &shr32(&commitment)));
    }

    /// THE cross-stack binding vector, computed from the real 4-batch
    /// aggregation session (ZiSK v0.18.0). `BINDING_VECTOR.md` next to
    /// this package records the same values; the server and L1-contract
    /// workstreams pin them verbatim. Update all of them together — they
    /// must never diverge.
    #[test]
    fn cross_stack_binding_vector() {
        const INNER_PROGRAM_VK: &str =
            "481748830df5c3b7aa5522333ace2c4b533352637b92fd3c83ecc506c5104ead";
        const ROOT_C_VADCOP_FINAL: &str =
            "cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";
        const COMMITMENTS: [&str; 4] = [
            "95693fd871251f2a04f558f94852d31d4f7b0cd38b0ee2c746bd2851dc701dca",
            "4962160e4e0addc72fe2178dbbf3c5882ca1033790bb968d4fa451485987f99b",
            "e697864dd72ddded6f1818db6618efff8e695714db8492ac50abc9f5d8b6221e",
            "3cbda79d374329af945a0b1d2d73c87b2cd2cadb69ab3d6c03166a690dfff898",
        ];
        const CHAINED_PI: &str =
            "000000004e755bc20431285db82f02b677f0fa43b0b4ae7298e2f489e1a45b78";
        const DIGEST: &str =
            "5f47db9b336cf84b7b7fc49ca77eadb5160e373dc8f12057d719f45d3b2fbd84";

        let program_vk = vk_words(unhex32(INNER_PROGRAM_VK));
        let vadcop_vk = vk_words(unhex32(ROOT_C_VADCOP_FINAL));
        let streams: Vec<Vec<u64>> = COMMITMENTS
            .iter()
            .map(|c| synth_stream(program_vk, vadcop_vk, unhex32(c)))
            .collect();

        // Intermediate chainedPI, via the public helpers.
        let pis: Vec<[u8; 32]> = streams
            .iter()
            .map(|s| ProofFrame::parse(s).unwrap().commitment_public_input())
            .collect();
        let mut chained = pis[0];
        for pi in &pis[1..] {
            chained = chain_step(&chained, pi);
        }
        assert_eq!(hex(&chained), CHAINED_PI, "chainedPI");

        // Final digest, via the Aggregator (the code path the guest runs).
        let mut agg = Aggregator::new();
        for s in &streams {
            agg.ingest(&ProofFrame::parse(s).unwrap()).unwrap();
        }
        let digest = agg.finalize().unwrap();
        assert_eq!(hex(&digest), DIGEST, "binding digest");
    }
}
