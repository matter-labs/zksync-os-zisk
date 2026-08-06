//! Execute a wire-encoded `BatchInput` (e.g. saved from the server's
//! `/ZiSK/{batch}/peek` endpoint) and print the commitment components — a
//! quick way to check what the guest computes for a specific batch when
//! debugging a proof-lane divergence.
//!
//! Usage: cargo run --bin run_batch_input -- <batch_input.bin>

use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::types::BatchInput;
use zksync_os_zisk_lib::wire;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: run_batch_input <batch_input.bin>");
    let bytes = std::fs::read(&path).expect("read input file");
    let input: BatchInput = wire::decode(&bytes).expect("decode BatchInput");

    println!(
        "wire_version={} spec_id={} protocol_minor={} chain_id={} blocks={}..={} txs={}",
        input.version,
        input.spec_id,
        input.protocol_version_minor,
        input.chain_id,
        input.blocks.first().map(|b| b.number).unwrap_or(0),
        input.blocks.last().map(|b| b.number).unwrap_or(0),
        input
            .blocks
            .iter()
            .map(|b| b.transactions.len())
            .sum::<usize>(),
    );

    let (_output, commitment, state_before, state_after, batch_hash) =
        executor::execute_and_commit_debug(&input);
    println!("state_before = {state_before}");
    println!("state_after  = {state_after}");
    println!("batch_hash   = {batch_hash}");
    println!("commitment   = {commitment}");
}
