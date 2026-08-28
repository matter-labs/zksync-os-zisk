//! ZiSK aggregator guest: verifies N `vadcop_final` proofs of the STF guest
//! and commits the L1 binding digest over their folded batch public inputs.
//!
//! Verification runs pil2-proofman's `proofman-verifier` via ZiSK's own
//! `ziskos::zisklib::verify_zisk_proof` (no_std, Poseidon2-16 transcript and
//! Merkle hashing through the ZiSK poseidon2 precompile). Only non-minimal
//! proofs are accepted: the minimal/compressed variant hashes with
//! Poseidon2-8, which has no precompile and would run the permutation in
//! software.
//!
//! Input framing (host writes consecutive `write_input_slice` frames; the
//! assembler is `aggregator_input` in `prover/`):
//!   slice 0: u64 LE — the number of proofs N (N >= 1)
//!   slice 1..=N: one serialized proof each, exactly the byte stream
//!     `cargo-zisk` clients obtain from `get_proof_bytes()`.
//!
//! Stream layout, section offsets, validation rules, and the committed
//! output (the settlement-layer-aligned binding digest) are defined
//! once in this package's library (`src/lib.rs`), which is host-tested and
//! shared with the input assembler; this binary only wires it to `ziskos`.

#![cfg_attr(all(target_os = "zkvm", target_vendor = "zisk"), no_main)]

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
ziskos::entrypoint!(main);

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
fn main() {
    use zksync_os_zisk_guest_aggregator::{
        parse_count_frame, words_from_bytes, Aggregator, ProofFrame,
    };

    let count_bytes = ziskos::io::read_slice();
    let n = parse_count_frame(count_bytes).unwrap_or_else(|e| panic!("count frame: {e}"));

    let mut aggregator = Aggregator::new();
    for i in 0..n {
        let proof_bytes = ziskos::io::read_slice();
        let words = words_from_bytes(proof_bytes).unwrap_or_else(|e| panic!("proof {i}: {e}"));
        let frame = ProofFrame::parse(words).unwrap_or_else(|e| panic!("proof {i}: {e}"));
        aggregator
            .ingest(&frame)
            .unwrap_or_else(|e| panic!("proof {i}: {e}"));
        assert!(
            ziskos::zisklib::verify_zisk_proof(frame.words()),
            "proof {i}: verification failed"
        );
    }

    let binding = aggregator
        .finalize()
        .unwrap_or_else(|e| panic!("finalize: {e}"));
    ziskos::io::commit_slice(&binding);
}

#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
fn main() {
    // The guest entrypoint exists only for the riscv64ima-zisk-zkvm-elf
    // target; host-side coverage of the shared logic lives in `cargo test`.
    eprintln!("zksync-os-zisk-guest-aggregator is a zkVM guest binary; run `cargo test` on the host");
    std::process::exit(2);
}
