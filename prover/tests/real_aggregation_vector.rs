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

const INNER_PROGRAM_VK: &str = "1d16f620e2bc7e58044df7ee8d4284422a0dd37cf151cf79ecf324c131e50468";
const ROOT_C_VADCOP_FINAL: &str =
    "cf2a309856f107b143836ada112806da71ae11567fa3f2d2050baba5381c7b7d";
const COMMITMENTS: [&str; 4] = [
    "6c41981c6fd0bd9a9262fe3dcc9fe4f0d8e142651f80316a8846d6922b5214ea",
    "1f56fcbd24636dc0a635bc51808d7db9eabf3914f66611c93cf37ea440a5fe27",
    "9d909d7416f29633c361bfc00073a9004423f0e1cc46105cdd24550543c0e41c",
    "6ca5ada4916397cfb1b07a2f115f21fedf7e4a14a827995b3c5b392966532ad6",
];
const DIGEST: &str = "7eabba6c7a68150706e10101195be54eaf3b39f699bc8da5f34c8033eedec13e";

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
