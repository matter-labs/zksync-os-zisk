//! ZiSK prover daemon library surface — exposed so the proof-file parsing
//! (mirrored `zisk-common` structs) is unit-testable against real
//! `cargo-zisk` output.

pub mod aggregator_input;
pub mod metrics;
pub mod prover;
pub mod sequencer_client;
