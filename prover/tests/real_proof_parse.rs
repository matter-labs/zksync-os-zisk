//! Regression test against a REAL `cargo-zisk prove --plonk` (ZiSK v0.18.0)
//! proof file — the artifact that settled plan item 2.1. Produced 2026-07-09
//! on an RTX 5090 for a v30 batch of the integrated validation run (guest
//! ELF c7d8e7dd…, batch commitment cross-checked against the guest
//! executor's re-execution of the same `BatchInput`).
//!
//! Guards the wire-layout facts the round-trip tests cannot see:
//! the publics region is ziskos's full 64-word (256-byte) output block.

use zksync_os_zisk_prover_service::prover::parse_proof_file;

const EXPECTED_PROGRAM_VK: &str =
    "8c524538f5d736a2885f95bbf173d23a72712a9929767c44bcedd358adcf1fd8";
const EXPECTED_COMMITMENT: &str =
    "b35685d5f5511ec665bc7918003b3fa0bc156b12b7421791f3cffdc3c1bb622c";
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
