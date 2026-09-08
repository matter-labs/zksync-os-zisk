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
        hex(&commitment(&out.public_values))
    );
    let tail = &out.public_values[96..out.public_values.len() - 32];
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

fn commitment(public_values: &[u8]) -> [u8; 32] {
    let mut digest = [0; 32];
    for (chunk, slot) in digest
        .chunks_exact_mut(4)
        .zip(public_values[32..96].chunks_exact(8))
    {
        assert_eq!(&slot[4..], &[0; 4], "non-canonical guest-public padding");
        chunk.copy_from_slice(&slot[..4]);
    }
    digest
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn commitment_unpacks_all_eight_u64_slots() {
        let expected = std::array::from_fn::<_, 32, _>(|i| i as u8 + 1);
        let mut values = [0; 576];
        for (chunk, slot) in expected
            .chunks_exact(4)
            .zip(values[32..96].chunks_exact_mut(8))
        {
            slot[..4].copy_from_slice(chunk);
        }
        assert_eq!(super::commitment(&values), expected);
    }
}
