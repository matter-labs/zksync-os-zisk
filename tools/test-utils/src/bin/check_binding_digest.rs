//! Recompute the aggregated-range binding digest from the four per-batch
//! commitments, following guest-aggregator/BINDING_VECTOR.md literally
//! (PI[i] = commitment_i >> 32, chained keccak fold, final digest) rather
//! than the aggregator guest's code path — the fixture-session workflow
//! compares this independent value against the aggregated proof's
//! publics[32..64].
//!
//! Usage: check_binding_digest <inner_program_vk> <root_c_vadcop_final>
//!                             <commitment_1> <commitment_2> <commitment_3> <commitment_4>

use alloy_primitives::B256;
use zksync_os_zisk_lib::hash::keccak256;

fn parse32(arg: &str) -> anyhow::Result<B256> {
    let hex = arg.strip_prefix("0x").unwrap_or(arg);
    anyhow::ensure!(hex.len() == 64, "{arg}: expected 32 hex bytes");
    Ok(hex.parse()?)
}

/// `uint256(word) >> 32`, carried as a 32-byte big-endian word.
fn shr32(word: &B256) -> B256 {
    let mut out = [0u8; 32];
    out[4..].copy_from_slice(&word.as_slice()[..28]);
    B256::from(out)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    anyhow::ensure!(
        args.len() == 6,
        "usage: check_binding_digest <inner_program_vk> <root_c> <c1> <c2> <c3> <c4>"
    );
    let inner_vk = parse32(&args[0])?;
    let root_c = parse32(&args[1])?;

    let mut chained = B256::ZERO;
    for (i, arg) in args[2..].iter().enumerate() {
        let pi = shr32(&parse32(arg)?);
        println!("PI[{i}] = {pi}");
        chained = if i == 0 {
            pi // initialHash == 0 → the seed is PI[0] itself
        } else {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(chained.as_slice());
            buf[32..].copy_from_slice(pi.as_slice());
            shr32(&keccak256(&buf))
        };
        println!("chained_after[{i}] = {chained}");
    }
    println!("chained_pi = {chained}");

    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(inner_vk.as_slice());
    buf[32..64].copy_from_slice(root_c.as_slice());
    buf[64..].copy_from_slice(chained.as_slice());
    println!("binding_digest = {}", keccak256(&buf));
    Ok(())
}
