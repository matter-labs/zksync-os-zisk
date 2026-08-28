//! Host-side input assembler for the ZiSK aggregator guest.
//!
//! Takes N per-batch proofs — `cargo-zisk prove` output files with a
//! Vadcop body (runs WITHOUT `--plonk`) or raw `get_proof_bytes()` streams
//! — and writes the aggregator guest's framed `input.bin`:
//!
//! ```text
//! frame   := [payload_len u64 LE][payload][zero-pad to 8-byte boundary]
//! input   := frame(N as u64 LE) ‖ frame(proof_1) ‖ … ‖ frame(proof_N)
//! ```
//!
//! This is exactly the layout `ziskos::io::read_input_slice` consumes
//! (`read_slice_zerocopy`: 8-byte length prefix, data padded to 8).
//! Every stream is validated with the guest's own parser
//! (`zksync-os-zisk-guest-aggregator` lib) before framing, so a malformed
//! or mixed-VK input fails on the host with a real error message instead
//! of a zkVM panic.

use anyhow::Context;
use std::path::Path;
use zksync_os_zisk_guest_aggregator as agg;

/// One ziskos input frame: `[len u64 LE][payload][zero-pad to 8]`.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let padded_len = payload.len().div_ceil(8) * 8;
    let mut out = Vec::with_capacity(8 + padded_len);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(8 + padded_len, 0);
    out
}

/// Split a framed input back into its payloads (round-trip/debug helper).
pub fn decode_frames(bytes: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        anyhow::ensure!(
            pos + 8 <= bytes.len(),
            "truncated length prefix at byte {pos}"
        );
        let len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        anyhow::ensure!(
            pos + len <= bytes.len(),
            "frame at byte {pos} claims {len} bytes past the end of input"
        );
        frames.push(bytes[pos..pos + len].to_vec());
        pos += len.div_ceil(8) * 8;
    }
    Ok(frames)
}

/// Assemble the aggregator guest input from N serialized proof streams.
pub fn assemble(streams: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(!streams.is_empty(), "at least one proof required");

    // Dry-run the guest's parsing + shared-VK validation on the host.
    let mut aggregator = agg::Aggregator::new();
    for (i, stream) in streams.iter().enumerate() {
        let words = agg::words_from_bytes(stream).map_err(|e| anyhow::anyhow!("proof {i}: {e}"))?;
        let frame = agg::ProofFrame::parse(words).map_err(|e| anyhow::anyhow!("proof {i}: {e}"))?;
        aggregator
            .ingest(&frame)
            .map_err(|e| anyhow::anyhow!("proof {i}: {e}"))?;
    }

    let mut out = encode_frame(&(streams.len() as u64).to_le_bytes());
    for stream in streams {
        out.extend_from_slice(&encode_frame(stream));
    }
    Ok(out)
}

/// Load one per-batch proof from disk: either a raw `get_proof_bytes()`
/// stream (exact [`agg::PROOF_STREAM_BYTES`] length that parses as a
/// non-minimal frame) or a `cargo-zisk` bincode proof file with a Vadcop
/// body.
pub fn load_proof_stream(path: &Path) -> anyhow::Result<Vec<u8>> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if data.len() == agg::PROOF_STREAM_BYTES
        && agg::words_from_bytes(&data)
            .ok()
            .and_then(|w| agg::ProofFrame::parse(w).ok())
            .is_some()
    {
        return Ok(data);
    }
    crate::prover::vadcop_stream_from_proof_file(path)
        .with_context(|| format!("{} is neither a raw vadcop_final stream nor a cargo-zisk proof file with a Vadcop body", path.display()))
}

/// A structurally exact but cryptographically invalid proof stream for
/// plumbing tests: correct sizes, non-minimal flag, leaf flag set, one
/// shared synthetic (program VK, vadcop VK) pair, and a commitment derived
/// from `index`. The guest parses it fully and fails only INSIDE
/// `verify_zisk_proof` — the expected outcome until real specimens exist.
/// Body words stay below the Goldilocks modulus (< 2^31 here) so failure
/// is a clean transcript/Merkle rejection, not a field-decode panic.
pub fn synthetic_stream(index: u32) -> Vec<u8> {
    let program_vk = [0xA5A5_0001u64, 0xA5A5_0002, 0xA5A5_0003, 0xA5A5_0004];
    let vadcop_vk = [0x5A5A_0001u64, 0x5A5A_0002, 0x5A5A_0003, 0x5A5A_0004];

    let mut words: Vec<u64> = Vec::with_capacity(agg::PROOF_STREAM_WORDS);
    words.push(0); // non-minimal
    words.push(agg::EXPECTED_N_PUBLICS);
    words.push(agg::IS_VADCOP_FINAL_PROOF);
    words.extend_from_slice(&program_vk);
    let mut publics = [0u64; agg::PUBLICS_WORDS];
    for (i, p) in publics.iter_mut().take(agg::COMMITMENT_WORDS).enumerate() {
        *p = (0x1000_0000u64 + index as u64) * 8 + i as u64;
    }
    words.extend_from_slice(&publics);
    // Deterministic sub-2^31 filler.
    words.extend(
        (0..agg::VADCOP_FINAL_BODY_WORDS)
            .map(|i| ((i as u64).wrapping_mul(0x9E37_79B9) ^ index as u64) % (1 << 31)),
    );
    words.extend_from_slice(&vadcop_vk);
    debug_assert_eq!(words.len(), agg::PROOF_STREAM_WORDS);

    let mut bytes = Vec::with_capacity(agg::PROOF_STREAM_BYTES);
    for w in &words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        for payload in [
            vec![],
            vec![1u8],
            vec![2u8; 7],
            vec![3u8; 8],
            vec![4u8; 9],
            vec![5u8; 4097],
        ] {
            let framed = encode_frame(&payload);
            assert_eq!(framed.len() % 8, 0, "frames are 8-byte aligned");
            let frames = decode_frames(&framed).unwrap();
            assert_eq!(frames, vec![payload]);
        }
    }

    #[test]
    fn decode_rejects_truncation() {
        let framed = encode_frame(&[1u8; 16]);
        assert!(decode_frames(&framed[..framed.len() - 8]).is_err());
        assert!(decode_frames(&framed[..4]).is_err());
    }

    #[test]
    fn assemble_roundtrip() {
        let streams = vec![
            synthetic_stream(0),
            synthetic_stream(1),
            synthetic_stream(2),
        ];
        let input = assemble(&streams).unwrap();

        let frames = decode_frames(&input).unwrap();
        assert_eq!(frames.len(), 4, "count frame + 3 proof frames");
        assert_eq!(frames[0], 3u64.to_le_bytes());
        for (frame, stream) in frames[1..].iter().zip(&streams) {
            assert_eq!(frame, stream);
            // Each payload still parses with the guest's parser.
            let words = agg::words_from_bytes(frame).unwrap();
            agg::ProofFrame::parse(words).unwrap();
        }
    }

    #[test]
    fn assemble_rejects_empty_and_malformed() {
        assert!(assemble(&[]).is_err());

        let mut bad = synthetic_stream(0);
        bad.truncate(bad.len() - 8);
        let err = assemble(&[bad]).unwrap_err().to_string();
        assert!(err.contains("proof 0"), "unexpected error: {err}");
    }

    #[test]
    fn assemble_rejects_mixed_vks() {
        let a = synthetic_stream(0);
        let mut b = synthetic_stream(1);
        // Flip a program-VK word in the second stream.
        let vk_off = (agg::HEADER_WORDS + agg::LEAF_FLAG_WORDS) * 8;
        b[vk_off] ^= 0xFF;
        let err = assemble(&[a, b]).unwrap_err().to_string();
        assert!(
            err.contains("program VK mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_accepts_raw_stream() {
        let dir = std::env::temp_dir().join(format!("zisk_agg_load_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("raw_stream.bin");
        let stream = synthetic_stream(9);
        std::fs::write(&path, &stream).unwrap();
        let loaded = load_proof_stream(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(loaded, stream);
    }

    /// A real cargo-zisk vadcop_final specimen (batch 1 of the
    /// binding-vector range) must load unchanged — the regression anchor
    /// for the stream framing accepted by the in-guest verifier.
    #[test]
    fn load_accepts_the_real_vadcop_fixture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/real_vadcop_final_zisk_v1.2.0-alpha.bin"
        );
        let loaded = load_proof_stream(Path::new(path)).unwrap();
        assert!(!loaded.is_empty());
    }

    /// The committed real fixture is a PLONK-wrapped proof — NOT a
    /// vadcop_final stream. The assembler must refuse it with an error
    /// that says so (real specimens need a no-`--plonk` cargo-zisk run).
    #[test]
    fn load_rejects_the_real_plonk_fixture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/real_proof_zisk_v1.2.0-alpha.bin"
        );
        let err = load_proof_stream(Path::new(path)).unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("Plonk"), "unexpected error: {chain}");
    }
}
