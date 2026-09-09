//! Regression test against a REAL PLONK proof file: batch 1 of the
//! binding-vector range, wrapped from the same `vadcop_final` stream that
//! `real_aggregation_vector.rs` checks.
//!
//! Guards the wire-layout facts the round-trip tests cannot see: the publics
//! region is ziskos's full 64-word output block at u64 width, so it occupies
//! 512 bytes and each word carries four significant bytes.
//!
//! The three expected values rotate with the fixture. The fixture-session
//! workflow produces both together.

use zksync_os_zisk_prover_service::prover::parse_proof_file;

const EXPECTED_PROGRAM_VK: &str =
    "189d6b11c50ef1db9885fed376479ed97dde719a59574a7946d8d612e25da97a";
const EXPECTED_COMMITMENT: &str =
    "63c7606faee0ee9eff230fec391e64c0c82a0277947973ce7f6f1c9088c821dd";
const EXPECTED_VADCOP_VK: &str = "564c2b1bcbd5932c81cfad1fa786a98372eb3d6495257c2d944544334f84382f";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The commitment's eight u32 words each sit in the low half of an
/// eight-byte slot, so read them back out of the widened publics region.
fn commitment(public_values: &[u8]) -> String {
    let mut out = Vec::with_capacity(32);
    for word in public_values[32..96].as_chunks::<8>().0 {
        out.extend_from_slice(&word[..4]);
    }
    hex(&out)
}

#[test]
fn parses_real_proof_file() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/real_proof_zisk_v1.2.0-alpha.bin"
    );
    let out = parse_proof_file(std::path::Path::new(path)).expect("parse real proof file");

    assert_eq!(out.proof.len(), 768, "PLONK proof size");
    assert_eq!(out.public_values.len(), 576, "wire public values size");
    assert_eq!(
        hex(&out.public_values[..32]),
        EXPECTED_PROGRAM_VK,
        "programVK prefix"
    );
    assert_eq!(
        commitment(&out.public_values),
        EXPECTED_COMMITMENT,
        "batch commitment words"
    );
    assert!(
        out.public_values[32..96]
            .as_chunks::<8>()
            .0
            .iter()
            .all(|w| w[4..] == [0u8; 4]),
        "each guest public is a u32 widened to a u64"
    );
    assert!(
        out.public_values[96..544].iter().all(|b| *b == 0),
        "unused guest output words must be zero"
    );
    assert_eq!(
        hex(&out.public_values[544..]),
        EXPECTED_VADCOP_VK,
        "vadcop VK suffix"
    );
}
