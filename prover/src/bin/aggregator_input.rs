//! Assemble an input file for the ZiSK aggregator guest.
//!
//! Inputs are per-batch `vadcop_final` proofs, given either as `cargo-zisk
//! prove` output files with a Vadcop body (runs WITHOUT `--plonk`) or as
//! raw `get_proof_bytes()` streams. `--synthetic N` instead generates N
//! structurally exact but cryptographically invalid streams to validate
//! the ziskemu plumbing before real specimens exist (the guest will parse
//! them and fail inside `verify_zisk_proof`).
//!
//! Example:
//!   aggregator_input -o input.bin batch1_vadcop_final.bin batch2_vadcop_final.bin
//!   aggregator_input -o input.bin --synthetic 2

use clap::Parser;
use std::path::PathBuf;
use zksync_os_zisk_guest_aggregator as agg;
use zksync_os_zisk_prover_service::aggregator_input::{
    assemble, load_proof_stream, synthetic_stream,
};

#[derive(Parser)]
#[command(about = "Assemble a framed input.bin for the ZiSK aggregator guest")]
struct Args {
    /// Output path for the framed guest input.
    #[arg(short, long)]
    output: PathBuf,

    /// Generate N synthetic (cryptographically invalid) proof streams
    /// instead of reading proof files. Plumbing validation only.
    #[arg(long, conflicts_with = "proofs")]
    synthetic: Option<u32>,

    /// Per-batch proof files (cargo-zisk Vadcop proof files or raw
    /// get_proof_bytes streams), in batch order.
    proofs: Vec<PathBuf>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// VK words rendered as the 32-byte big-endian value used everywhere else
/// (the server's `zisk_program_vk` config, the wire public values).
fn vk_hex(words: &[u64]) -> String {
    let mut bytes = Vec::with_capacity(words.len() * 8);
    for w in words {
        bytes.extend_from_slice(&w.to_be_bytes());
    }
    format!("0x{}", hex(&bytes))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let streams: Vec<Vec<u8>> = match args.synthetic {
        Some(n) => {
            anyhow::ensure!(n >= 1, "--synthetic requires N >= 1");
            eprintln!(
                "generating {n} synthetic proof streams (cryptographically invalid; plumbing only)"
            );
            (0..n).map(synthetic_stream).collect()
        }
        None => {
            anyhow::ensure!(
                !args.proofs.is_empty(),
                "no proof files given (or use --synthetic N)"
            );
            args.proofs
                .iter()
                .map(|p| load_proof_stream(p))
                .collect::<anyhow::Result<_>>()?
        }
    };

    let input = assemble(&streams)?;

    // Report what was bound (parse errors were already caught by assemble).
    let first = agg::ProofFrame::parse(agg::words_from_bytes(&streams[0]).unwrap()).unwrap();
    eprintln!("proofs:          {}", streams.len());
    eprintln!("inner programVK: {}", vk_hex(first.program_vk()));
    eprintln!("vadcopVK:        {}", vk_hex(first.vadcop_vk()));
    for (i, stream) in streams.iter().enumerate() {
        let frame = agg::ProofFrame::parse(agg::words_from_bytes(stream).unwrap()).unwrap();
        eprintln!("  proof {i}: commitment 0x{}", hex(&frame.commitment()));
    }

    std::fs::write(&args.output, &input)?;
    eprintln!("wrote {} bytes to {}", input.len(), args.output.display());
    Ok(())
}
