//! Binding-vector checks over REAL `cargo-zisk` (ZiSK v0.18.0)
//! `vadcop_final` proofs: load the proof files, parse them with the
//! guest's own frame parser, run the `Aggregator` (the exact code path the
//! guest executes, host keccak backend), and assert the values pinned in
//! `guest-aggregator/BINDING_VECTOR.md`.
//!
//! Two levels of coverage:
//! - [`binding_vector_batch1_matches_committed_fixture`] runs
//!   UNCONDITIONALLY against the committed batch-1 fixture
//!   (`tests/data/real_vadcop_final_zisk_v0.18.0.bin`), so a normal CI run
//!   verifies the pinned `innerProgramVK`, `rootCVadcopFinal`, and
//!   `commitment_1` rather than passing while checking nothing.
//! - [`real_proofs_reproduce_binding_vector`] reproduces the full 4-batch
//!   chained digest, but the other three ~370 KB proofs live outside the
//!   repo; point `ZISK_AGG_SESSION_DIR` at a directory holding
//!   `vadcop-batch-{1..4}.bin` to run it. Absent the variable it skips
//!   LOUDLY (see the note there) instead of masquerading as a pass.

use zksync_os_zisk_guest_aggregator as agg;
use zksync_os_zisk_prover_service::aggregator_input::load_proof_stream;

const INNER_PROGRAM_VK: &str = "44e3d132399c8f3a03ce9672ba0ca00c6503db918731c7ab46d6faea445236ec";
const ROOT_C_VADCOP_FINAL: &str =
    "cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";
const COMMITMENTS: [&str; 4] = [
    "5aa9a30847d37bb20955cfe6a65c916d4d0c504c8e5bb0965db8a90aba1e9938",
    "167bf6f9edbe48835b6b60e98af53552b0126765a804b86a3d7749daf05a5f4e",
    "8f03a8b3b8b78ef7ab5004817c9ebf211b09533b9a0ad86440396f4605ab794b",
    "3db0606d441cb57e9c621be9052e759db43e7c5c608c6e810ce673d9a4503c45",
];
const DIGEST: &str = "8d3dc379548b65d0ed7df762dc646bf46fdbdf628cfe483479392ea8159e405b";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn vk_hex(words: &[u64]) -> String {
    let mut bytes = Vec::with_capacity(words.len() * 8);
    for w in words {
        bytes.extend_from_slice(&w.to_be_bytes());
    }
    hex(&bytes)
}

/// Unconditional coverage: the committed batch-1 `vadcop_final` fixture
/// (batch 1 of the binding-vector range) must reproduce the pinned
/// `innerProgramVK`, `rootCVadcopFinal`, and `commitment_1` through the
/// guest's own parser. This is the aggregation-path analogue of
/// `real_proof_parse.rs` and guarantees a green CI run has actually checked
/// the shared wire constants the L1 range verifier depends on.
#[test]
fn binding_vector_batch1_matches_committed_fixture() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/real_vadcop_final_zisk_v0.18.0.bin"
    );
    let stream = load_proof_stream(std::path::Path::new(path))
        .expect("load committed batch-1 vadcop_final fixture");

    let words = agg::words_from_bytes(&stream).expect("stream words");
    let frame = agg::ProofFrame::parse(words).expect("parse batch-1 frame");

    assert_eq!(
        hex(&frame.commitment()),
        COMMITMENTS[0],
        "batch-1 commitment"
    );
    assert_eq!(
        vk_hex(frame.program_vk()),
        INNER_PROGRAM_VK,
        "innerProgramVK"
    );
    assert_eq!(
        vk_hex(frame.vadcop_vk()),
        ROOT_C_VADCOP_FINAL,
        "rootCVadcopFinal"
    );
}

#[test]
fn real_proofs_reproduce_binding_vector() {
    let Ok(dir) = std::env::var("ZISK_AGG_SESSION_DIR") else {
        // LOUD skip: the full 4-batch digest needs three more ~370 KB
        // proofs that do not live in the repo. The batch-1 fixture is still
        // checked unconditionally above, so a green CI run is never "checked
        // nothing"; only the cross-batch chaining is uncovered here.
        eprintln!(
            "NOTE: real_proofs_reproduce_binding_vector SKIPPED. Set \
             ZISK_AGG_SESSION_DIR to a directory containing \
             vadcop-batch-{{1..4}}.bin to reproduce the full 4-batch \
             chained digest. The committed batch-1 fixture is still \
             verified unconditionally by \
             binding_vector_batch1_matches_committed_fixture."
        );
        return;
    };
    let dir = std::path::Path::new(&dir);

    let streams: Vec<Vec<u8>> = (1..=4)
        .map(|i| {
            load_proof_stream(&dir.join(format!("vadcop-batch-{i}.bin")))
                .unwrap_or_else(|e| panic!("loading vadcop-batch-{i}.bin: {e:#}"))
        })
        .collect();

    let mut aggregator = agg::Aggregator::new();
    for (i, stream) in streams.iter().enumerate() {
        let words = agg::words_from_bytes(stream).unwrap();
        let frame = agg::ProofFrame::parse(words).unwrap();
        assert_eq!(
            hex(&frame.commitment()),
            COMMITMENTS[i],
            "batch {} commitment",
            i + 1
        );
        if i == 0 {
            assert_eq!(
                vk_hex(frame.program_vk()),
                INNER_PROGRAM_VK,
                "innerProgramVK"
            );
            assert_eq!(
                vk_hex(frame.vadcop_vk()),
                ROOT_C_VADCOP_FINAL,
                "rootCVadcopFinal"
            );
        }
        aggregator.ingest(&frame).unwrap();
    }

    let digest = aggregator.finalize().unwrap();
    assert_eq!(hex(&digest), DIGEST, "binding digest");
}
