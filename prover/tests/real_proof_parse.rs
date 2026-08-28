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
    "1d16f620e2bc7e58044df7ee8d4284422a0dd37cf151cf79ecf324c131e50468";
const EXPECTED_COMMITMENT: &str =
    "6c41981c6fd0bd9a9262fe3dcc9fe4f0d8e142651f80316a8846d6922b5214ea";
const EXPECTED_VADCOP_VK: &str = "cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The commitment's eight u32 words each sit in the low half of an
/// eight-byte slot, so read them back out of the widened publics region.
fn commitment(public_values: &[u8]) -> String {
    let mut out = Vec::with_capacity(32);
    for word in public_values[32..96].chunks_exact(8) {
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
            .chunks_exact(8)
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
