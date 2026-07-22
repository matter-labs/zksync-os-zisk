//! Inspect a real `cargo-zisk prove --plonk` proof file: parse it with the
//! daemon's mirrored structs, dump the assembled wire sections, and print
//! the full PROOF / PUBLIC_VALUES hex — the constants the era-contracts
//! real-proof fixture test pins, so VK bumps re-derive them from a fresh
//! proof in one command.
//!
//! Usage: cargo run --bin inspect_proof -- <proof.bin>

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: inspect_proof <proof.bin>");
    let out = zksync_os_zisk_prover_service::prover::parse_proof_file(std::path::Path::new(&path))
        .expect("parse proof file");
    println!("proof bytes: {}", out.proof.len());
    println!("public values bytes: {}", out.public_values.len());
    println!("program_vk   = 0x{}", hex(&out.public_values[..32]));
    println!(
        "publics[0..32]  (commitment) = 0x{}",
        hex(&out.public_values[32..64])
    );
    let tail = &out.public_values[64..out.public_values.len() - 32];
    println!(
        "publics tail nonzero bytes: {}",
        tail.iter().filter(|b| **b != 0).count()
    );
    let n = out.public_values.len();
    println!("vadcop_vk    = 0x{}", hex(&out.public_values[n - 32..]));
    println!("PROOF({}): {}", out.proof.len(), hex(&out.proof));
    println!(
        "PUBLIC_VALUES({}): {}",
        out.public_values.len(),
        hex(&out.public_values)
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
