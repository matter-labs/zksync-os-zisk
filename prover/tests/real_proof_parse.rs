//! Regression test against a REAL PLONK proof file (ZiSK v0.18.0): batch 1
//! of the binding-vector range, wrapped by `cargo-zisk wrap-proof --plonk`
//! on an RTX 5090 on 2026-08-04 from the same `vadcop_final` stream that
//! `real_aggregation_vector.rs` checks. Guest ELF sha256 32911f12….
//!
//! Guards the wire-layout facts the round-trip tests cannot see:
//! the publics region is ziskos's full 64-word (256-byte) output block.

use zksync_os_zisk_prover_service::prover::parse_proof_file;

const EXPECTED_PROGRAM_VK: &str =
    "1d16f620e2bc7e58044df7ee8d4284422a0dd37cf151cf79ecf324c131e50468";
const EXPECTED_COMMITMENT: &str =
    "6c41981c6fd0bd9a9262fe3dcc9fe4f0d8e142651f80316a8846d6922b5214ea";
const EXPECTED_VADCOP_VK: &str = "cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn parses_real_v0_18_proof_file() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/real_proof_zisk_v0.18.0.bin"
    );
    let out = parse_proof_file(std::path::Path::new(path)).expect("parse real proof file");

    assert_eq!(out.proof.len(), 768, "PLONK proof size");
    assert_eq!(out.public_values.len(), 320, "wire public values size");
    assert_eq!(
        hex(&out.public_values[..32]),
        EXPECTED_PROGRAM_VK,
        "programVK prefix"
    );
    assert_eq!(
        hex(&out.public_values[32..64]),
        EXPECTED_COMMITMENT,
        "batch commitment word"
    );
    assert!(
        out.public_values[64..288].iter().all(|b| *b == 0),
        "unused guest output words must be zero"
    );
    assert_eq!(
        hex(&out.public_values[288..]),
        EXPECTED_VADCOP_VK,
        "vadcop VK suffix"
    );
}
