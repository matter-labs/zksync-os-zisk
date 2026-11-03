//! Regression test against a REAL pilfflonk SNARK file: the aggregated proof
//! of the binding-vector range, wrapped over the same `vadcop_final` streams
//! that `real_aggregation_vector.rs` checks. It is the file the daemon submits
//! in aggregated mode.
//!
//! Guards the wire-layout facts the round-trip tests cannot see: the mirrored
//! bincode shape of ZiSK's SNARK file, and the publics region, ziskos's full
//! 64-word output block at u64 width, so it occupies 512 bytes and each word
//! carries four significant bytes.
//!
//! The fixture publisher (`.github/scripts/apply-fixture-session.py`) rotates
//! the three expected values together with the fixture.

use zksync_os_zisk_prover_service::prover::parse_proof_file;

const AGGREGATOR_PROGRAM_VK: &str =
    "e7f72bf4c1825a6f852e65fc872c810320218c63ed41cf9bb4345737a4ac31ec";
const DIGEST: &str = "5afe2e89a27ddd841b343cff7fb3a9f3c0dc18b0d6bc7d685fbfa55af59c9bd0";
const ROOT_C_VADCOP_FINAL: &str =
    "e9414e134bb6945a148a79d44c8e850e5ef582a2b0e8dbfb2428ff0a515a6e66";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The digest's eight u32 words each sit in the low half of an eight-byte
/// slot, so read them back out of the widened publics region.
fn digest(public_values: &[u8]) -> String {
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
        "/tests/data/real_pilfflonk_aggregate_zisk_v1.4.0-alpha.bin"
    );
    let out = parse_proof_file(std::path::Path::new(path)).expect("parse real proof file");

    assert_eq!(out.proof.len(), 69 * 32, "pilfflonk proof size");
    assert_eq!(out.public_values.len(), 576, "wire public values size");
    assert_eq!(
        hex(&out.public_values[..32]),
        AGGREGATOR_PROGRAM_VK,
        "programVK prefix"
    );
    assert_eq!(digest(&out.public_values), DIGEST, "binding digest words");
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
        ROOT_C_VADCOP_FINAL,
        "vadcop VK suffix"
    );
}
