//! Bodies of the wired ZiSK crypto precompile hooks.
//!
//! Each function here is the target-independent logic behind a `#[no_mangle]`
//! C-ABI hook in `main.rs` (the symbols `lib/src/crypto/ffi.rs` binds on the
//! ZiSK target). They are backed by `ziskos::zisklib`, which dispatches to
//! the ZiSK accelerated syscalls/fcalls on the zkVM target and to software
//! fallbacks on native targets — so this exact code is unit-testable on the
//! host, where the tests below compare it bit-for-bit against REVM's
//! `DefaultCrypto` reference (the semantics the native execution side of the
//! equivalence check uses).
//!
//! Contract per hook (see `lib/src/crypto/impls.rs` for the caller side):
//! - `sha256`: 32-byte digest, FIPS 180-4.
//! - `bn254_g1_add`/`bn254_g1_mul`: 64-byte big-endian affine points
//!   (infinity = all zeros); returns 0 = success, 1 = success-infinity,
//!   2 = coordinate not in field, 3 = point not on curve.
//! - `bn254_pairing_check`: `num_pairs` × 192-byte (G1 ‖ G2, EVM byte order:
//!   G2 = x_im ‖ x_re ‖ y_im ‖ y_re) elements; returns 0 = product is one,
//!   1 = product is not one, 2..=6 = validation error (any error halts the
//!   precompile, exactly like the reference's parse errors).
//! - `modexp`: EIP-198 semantics; writes `base^exp mod modulus` big-endian,
//!   left-zero-padded to `modulus.len()`, returns the written length.
//! - `secp256r1_verify`: RIP-7212 semantics (r, s ∈ [1, n-1], pk a canonical
//!   non-identity curve point, high-s accepted).

use ziskos::zisklib;

/// BN254 base-field modulus p, big-endian:
/// 21888242871839275222246405745257275088696311157297823662689037894645226208583.
const BN254_FP_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
    0xfd, 0x47,
];

/// SHA-256 digest via the ZiSK `sha256f` compression circuit (software
/// `sha2::compress256` on native).
#[inline]
pub fn sha256(input: &[u8]) -> [u8; 32] {
    zisklib::sha256(input)
}

/// BN254 G1 addition with EIP-196 validation semantics.
///
/// zisklib's `add_complete_bn254` performs exactly the reference checks
/// (canonical coordinates, on-curve, (0,0) = infinity) and returns the
/// matching codes, so this is a pure format-conversion wrapper around the
/// `bn254_curve_add`/`bn254_curve_dbl` syscalls.
pub fn bn254_g1_add(p1: &[u8; 64], p2: &[u8; 64], out: &mut [u8; 64]) -> u8 {
    let a = zisklib::g1_bytes_be_to_u64_le_bn254(p1);
    let b = zisklib::g1_bytes_be_to_u64_le_bn254(p2);
    match zisklib::add_complete_bn254(&a, &b) {
        // Identity is encoded as all zeros (EIP-196 output format).
        Ok(sum) if sum == [0u64; 8] => {
            out.fill(0);
            1
        }
        Ok(sum) => {
            g1_limbs_le_to_bytes_be(&sum, out);
            0
        }
        Err(code) => code,
    }
}

/// BN254 G1 scalar multiplication with EIP-196 validation semantics.
///
/// The scalar is an arbitrary 256-bit integer; zisklib reduces it mod the
/// group order r before the double-and-add loop, which yields the same point
/// as the reference's unreduced `mul_bigint` (the point has order r).
pub fn bn254_g1_mul(point: &[u8; 64], scalar: &[u8; 32], out: &mut [u8; 64]) -> u8 {
    let p = zisklib::g1_bytes_be_to_u64_le_bn254(point);
    let k = zisklib::scalar_bytes_be_to_u64_le_bn254(scalar);
    match zisklib::mul_complete_bn254(&p, &k) {
        Ok(product) if product == [0u64; 8] => {
            out.fill(0);
            1
        }
        Ok(product) => {
            g1_limbs_le_to_bytes_be(&product, out);
            0
        }
        Err(code) => code,
    }
}

/// BN254 pairing check with EIP-197 validation semantics.
///
/// `pairs` is `num_pairs` × 192 bytes. Coordinate canonicality (< p) is
/// checked here for EVERY coordinate of every pair before delegating to
/// zisklib: the reference (revm's arkworks backend) parses each Fq with a
/// canonical check regardless of the partner point, while zisklib's
/// `pairing_check_bn254` short-circuits pairs containing an infinity point
/// and would accept a non-canonical on-curve-mod-p coordinate there (e.g.
/// x = p + 1 next to an infinity partner). On-curve and G2-subgroup checks
/// are zisklib's, which match the reference for canonical inputs.
pub fn bn254_pairing_check(pairs: &[u8]) -> u8 {
    debug_assert!(pairs.len().is_multiple_of(192));
    let num_pairs = pairs.len() / 192;

    let mut g1_points: Vec<[u64; 8]> = Vec::with_capacity(num_pairs);
    let mut g2_points: Vec<[u64; 16]> = Vec::with_capacity(num_pairs);
    for pair in pairs.chunks_exact(192) {
        let g1: &[u8; 64] = pair[..64].try_into().unwrap();
        let g2: &[u8; 128] = pair[64..].try_into().unwrap();

        if !fq_is_canonical(&g1[..32]) || !fq_is_canonical(&g1[32..]) {
            return 2; // G1 coordinate not in field
        }
        if g2.chunks_exact(32).any(|c| !fq_is_canonical(c)) {
            return 4; // G2 coordinate not in field
        }

        g1_points.push(zisklib::g1_bytes_be_to_u64_le_bn254(g1));
        g2_points.push(zisklib::g2_bytes_be_to_u64_le_bn254(g2));
    }

    match zisklib::pairing_check_bn254(&g1_points, &g2_points) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(code) => code,
    }
}

/// EIP-198 modular exponentiation.
///
/// Writes `base^exp mod modulus` big-endian, left-zero-padded to
/// `modulus.len()` (== `out.len()`), and returns the written length.
/// `modulus == 0` (including a zero-length modulus) yields all zeros, like
/// the reference. The byte↔limb conversions mirror zisklib's own
/// `modexp_bytes_c` (which is crate-private); the big-int core is zisklib's
/// `modexp` over the `arith256` syscalls.
pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8], out: &mut [u8]) -> usize {
    debug_assert_eq!(out.len(), modulus.len());
    // Zero modulus short-circuit: keeps EVM semantics (result is all zeros)
    // and stays clear of zisklib's debug-only non-zero-modulus assertions.
    if modulus.iter().all(|&b| b == 0) {
        out.fill(0);
        return out.len();
    }

    let base_u256 = be_bytes_to_u256_le(base);
    let exp_u64 = be_bytes_to_u64_limbs(exp);
    let modulus_u256 = be_bytes_to_u256_le(modulus);

    let result = zisklib::modexp(&base_u256, &exp_u64, &modulus_u256);

    u256_le_to_bytes_be(&result, out);
    out.len()
}

/// RIP-7212 / EIP-7951 secp256r1 (P-256) ECDSA verification.
///
/// zisklib's `ecdsa_verify_secp256r1` enforces exactly the reference checks
/// (r, s ∈ [1, n-1]; pk canonical, non-identity, on curve; high-s accepted;
/// the message scalar acts mod n) on top of the `secp256r1_add`/`dbl`
/// syscalls and the ecdsa-verify fcall hint.
///
/// EXCEPTION — public keys with x = 0, i.e. the two curve points (0, ±√b)
/// (crafted-key territory; a random key hits them with probability ~2⁻²⁵⁵):
/// the fcall hint implementation behind zisklib (`fcalls_impl`, shared
/// verbatim by native runs, ziskemu, and the prover through the fcall-ID
/// proxy) encodes the point at infinity as (0, 0) and tests x-equality
/// BEFORE its identity checks, so its first accumulator step 𝒪 + PK takes
/// the "equal x, different y ⇒ inverse points ⇒ 𝒪" branch and drops PK's
/// top-bit contribution from the hinted R. zisklib's in-circuit equation
/// check [z]G + [r]PK − [s]R = 𝒪 is sound — a corrupted hint can only
/// reject valid signatures, never accept invalid ones — so exactly this pk
/// class mis-verdicts (found by the 2026-07-11 corpus round 2: 4
/// osaka_eip7951 cases). Route it to REVM's software reference
/// (`DefaultCrypto` → the p256 crate), bit-identical to the native side of
/// the equivalence check by construction; it is already compiled into the
/// guest, and the cost is irrelevant at ~never-hit frequency. Drop this
/// branch when upstream fixes the hint (see the tripwire test below).
pub fn secp256r1_verify(msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
    if pk[..32].iter().all(|&b| b == 0) {
        use revm::precompile::{Crypto, DefaultCrypto};
        return DefaultCrypto.secp256r1_verify_signature(msg, sig, pk);
    }
    let z = be_bytes_to_u64_le_4(msg[..32].try_into().unwrap());
    let r = be_bytes_to_u64_le_4(sig[..32].try_into().unwrap());
    let s = be_bytes_to_u64_le_4(sig[32..].try_into().unwrap());
    let x = be_bytes_to_u64_le_4(pk[..32].try_into().unwrap());
    let y = be_bytes_to_u64_le_4(pk[32..].try_into().unwrap());
    let pk_limbs = [x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]];
    zisklib::ecdsa_verify_secp256r1(&pk_limbs, &z, &r, &s)
}

// ==================== conversion helpers ====================

/// A 32-byte big-endian field element is canonical iff it is < p.
#[inline]
fn fq_is_canonical(be: &[u8]) -> bool {
    debug_assert_eq!(be.len(), 32);
    be < &BN254_FP_BE[..]
}

/// Inverse of zisklib's `g1_bytes_be_to_u64_le_bn254`: [x0..x3, y0..y3]
/// little-endian limbs → 64-byte big-endian x ‖ y.
fn g1_limbs_le_to_bytes_be(limbs: &[u64; 8], out: &mut [u8; 64]) {
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&limbs[3 - i].to_be_bytes());
        out[32 + i * 8..32 + (i + 1) * 8].copy_from_slice(&limbs[7 - i].to_be_bytes());
    }
}

/// 32 big-endian bytes → 4 little-endian u64 limbs.
fn be_bytes_to_u64_le_4(be: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[3 - i] = u64::from_be_bytes(be[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    limbs
}

/// Arbitrary-length big-endian bytes → little-endian u64 limbs with leading
/// zeros stripped (at least one limb). Mirrors zisklib's private helper.
fn be_bytes_to_u64_limbs(bytes: &[u8]) -> Vec<u64> {
    if bytes.is_empty() {
        return vec![0];
    }
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    let bytes = &bytes[first_nonzero..];

    let mut limbs = vec![0u64; bytes.len().div_ceil(8)];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= (byte as u64) << ((i % 8) * 8);
    }
    limbs
}

/// Arbitrary-length big-endian bytes → little-endian `U256` limbs (u64 limbs
/// zero-padded up to a multiple of four). Mirrors zisklib's private helper.
fn be_bytes_to_u256_le(bytes: &[u8]) -> Vec<zisklib::U256> {
    let limbs = be_bytes_to_u64_limbs(bytes);
    let padded_len = limbs.len().next_multiple_of(4);
    let mut padded = vec![0u64; padded_len];
    padded[..limbs.len()].copy_from_slice(&limbs);
    zisklib::U256::flat_to_slice(&padded).to_vec()
}

/// Little-endian `U256` limbs → big-endian bytes, right-aligned into `out`
/// (zero-filled on the left). Mirrors zisklib's private helper.
fn u256_le_to_bytes_be(limbs: &[zisklib::U256], out: &mut [u8]) {
    let flat = zisklib::U256::slice_to_flat(limbs);
    let out_len = out.len();
    out.fill(0);
    for (i, &limb) in flat.iter().enumerate() {
        for j in 0..8 {
            let pos_from_end = i * 8 + j;
            if pos_from_end < out_len {
                out[out_len - 1 - pos_from_end] = ((limb >> (j * 8)) & 0xff) as u8;
            }
        }
    }
}

// ==================== host-side reference tests ====================
//
// On native targets zisklib routes every syscall/fcall through software
// fallbacks, so these tests exercise the exact hook logic the guest runs
// and compare it against REVM's `DefaultCrypto` — the same reference the
// native side of the corpus equivalence check executes.
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    use revm::precompile::{Crypto, DefaultCrypto};

    /// BN254 group order r, big-endian.
    const BN254_FR_BE: [u8; 32] = hex!(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
    );
    /// secp256r1 group order n, big-endian.
    const P256_N_BE: [u8; 32] = hex!(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    );

    fn g1_add_both(p1: &[u8; 64], p2: &[u8; 64]) -> (Result<[u8; 64], ()>, Result<[u8; 64], ()>) {
        let mut out = [0u8; 64];
        let code = bn254_g1_add(p1, p2, &mut out);
        let ours = match code {
            0 | 1 => Ok(out),
            _ => Err(()),
        };
        let reference = DefaultCrypto.bn254_g1_add(p1, p2).map_err(|_| ());
        (ours, reference)
    }

    fn g1_mul_both(
        point: &[u8; 64],
        scalar: &[u8; 32],
    ) -> (Result<[u8; 64], ()>, Result<[u8; 64], ()>) {
        let mut out = [0u8; 64];
        let code = bn254_g1_mul(point, scalar, &mut out);
        let ours = match code {
            0 | 1 => Ok(out),
            _ => Err(()),
        };
        let reference = DefaultCrypto.bn254_g1_mul(point, scalar).map_err(|_| ());
        (ours, reference)
    }

    fn pairing_both(pairs: &[u8]) -> (Result<bool, ()>, Result<bool, ()>) {
        let ours = match bn254_pairing_check(pairs) {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(()),
        };
        let ref_pairs: Vec<(&[u8], &[u8])> = pairs
            .chunks_exact(192)
            .map(|p| (&p[..64], &p[64..]))
            .collect();
        let reference = DefaultCrypto.bn254_pairing_check(&ref_pairs).map_err(|_| ());
        (ours, reference)
    }

    fn check_modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; modulus.len()];
        let written = modexp(base, exp, modulus, &mut out);
        assert_eq!(written, modulus.len());

        // Reference output is unpadded big-endian; the precompile left-pads
        // it to modulus length (`left_pad_vec_be`), which we replicate here.
        let reference = DefaultCrypto.modexp(base, exp, modulus).unwrap();
        let mut ref_padded = vec![0u8; modulus.len()];
        let n = reference.len().min(modulus.len());
        ref_padded[modulus.len() - n..].copy_from_slice(&reference[reference.len() - n..]);

        assert_eq!(out, ref_padded, "modexp mismatch (base {base:02x?}, exp {exp:02x?}, mod {modulus:02x?})");
        out
    }

    fn check_p256(msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        let ours = secp256r1_verify(msg, sig, pk);
        let reference = DefaultCrypto.secp256r1_verify_signature(msg, sig, pk);
        assert_eq!(ours, reference, "p256 verify mismatch");
        ours
    }

    // ---------- SHA-256 ----------

    #[test]
    fn sha256_nist_vectors() {
        // FIPS 180-4 / NIST CAVS known-answer vectors.
        assert_eq!(
            sha256(b""),
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc"),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
        assert_eq!(
            sha256(&vec![b'a'; 1_000_000]),
            hex!("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn sha256_matches_reference_across_lengths() {
        // Cover every padding branch (block boundaries at 55/56/64 bytes).
        for len in 0..=130usize {
            let input: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(sha256(&input), DefaultCrypto.sha256(&input), "len {len}");
        }
    }

    // ---------- BN254 add ----------

    #[test]
    fn bn254_add_eip196_vector() {
        let p1: [u8; 64] = hex!(
            "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9"
            "063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266"
        );
        let p2: [u8; 64] = hex!(
            "07c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed"
            "06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7"
        );
        let expected: [u8; 64] = hex!(
            "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703"
            "301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915"
        );
        let (ours, reference) = g1_add_both(&p1, &p2);
        assert_eq!(ours, Ok(expected));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bn254_add_identity_and_inverse_cases() {
        let zero = [0u8; 64];
        let mut gen = [0u8; 64];
        gen[31] = 1; // x = 1
        gen[63] = 2; // y = 2 — the G1 generator

        // 0 + 0 = 0
        let (ours, reference) = g1_add_both(&zero, &zero);
        assert_eq!(ours, Ok(zero));
        assert_eq!(ours, reference);

        // P + 0 = P and 0 + P = P
        let (ours, reference) = g1_add_both(&gen, &zero);
        assert_eq!(ours, Ok(gen));
        assert_eq!(ours, reference);
        let (ours, reference) = g1_add_both(&zero, &gen);
        assert_eq!(ours, Ok(gen));
        assert_eq!(ours, reference);

        // P + (-P) = 0: -G = (1, p - 2)
        let mut neg_gen = gen;
        let mut y = BN254_FP_BE;
        y[31] -= 2; // p ends in 0x47, no borrow
        neg_gen[32..].copy_from_slice(&y);
        let (ours, reference) = g1_add_both(&gen, &neg_gen);
        assert_eq!(ours, Ok(zero));
        assert_eq!(ours, reference);

        // P + P = 2P (doubling branch)
        let (ours, reference) = g1_add_both(&gen, &gen);
        assert!(ours.is_ok());
        assert_eq!(ours, reference);
    }

    #[test]
    fn bn254_add_invalid_inputs() {
        let mut gen = [0u8; 64];
        gen[31] = 1;
        gen[63] = 2;

        // Not on curve: (1, 1)
        let mut bad = [0u8; 64];
        bad[31] = 1;
        bad[63] = 1;
        let (ours, reference) = g1_add_both(&bad, &gen);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
        let (ours, reference) = g1_add_both(&gen, &bad);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        // Non-canonical coordinate: x = p (≡ 0 mod p, but rejected as >= p)
        let mut non_canonical = [0u8; 64];
        non_canonical[..32].copy_from_slice(&BN254_FP_BE);
        non_canonical[63] = 2;
        let (ours, reference) = g1_add_both(&non_canonical, &gen);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        // Non-canonical but on-curve mod p: x = p + 1, y = 2 (reduces to G)
        let mut x = BN254_FP_BE;
        x[31] += 1;
        let mut sneaky = [0u8; 64];
        sneaky[..32].copy_from_slice(&x);
        sneaky[63] = 2;
        let (ours, reference) = g1_add_both(&sneaky, &gen);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    // ---------- BN254 mul ----------

    #[test]
    fn bn254_mul_eip196_vector() {
        let point: [u8; 64] = hex!(
            "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7"
            "21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204"
        );
        let scalar: [u8; 32] =
            hex!("00000000000000000000000000000000000000000000000011138ce750fa15c2");
        let expected: [u8; 64] = hex!(
            "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c"
            "031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc"
        );
        let (ours, reference) = g1_mul_both(&point, &scalar);
        assert_eq!(ours, Ok(expected));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bn254_mul_edge_scalars() {
        let mut gen = [0u8; 64];
        gen[31] = 1;
        gen[63] = 2;
        let zero = [0u8; 64];

        // k = 0 → infinity
        let (ours, reference) = g1_mul_both(&gen, &[0u8; 32]);
        assert_eq!(ours, Ok(zero));
        assert_eq!(ours, reference);

        // 0 * k → infinity (point at infinity in, any scalar)
        let mut k7 = [0u8; 32];
        k7[31] = 7;
        let (ours, reference) = g1_mul_both(&zero, &k7);
        assert_eq!(ours, Ok(zero));
        assert_eq!(ours, reference);

        // k = 1, 2, 7 and a large unreduced scalar (max) against reference
        for k in [
            {
                let mut k = [0u8; 32];
                k[31] = 1;
                k
            },
            {
                let mut k = [0u8; 32];
                k[31] = 2;
                k
            },
            k7,
            [0xffu8; 32],
        ] {
            let (ours, reference) = g1_mul_both(&gen, &k);
            assert!(ours.is_ok());
            assert_eq!(ours, reference, "scalar {k:02x?}");
        }

        // k = r (group order) → infinity
        let (ours, reference) = g1_mul_both(&gen, &BN254_FR_BE);
        assert_eq!(ours, Ok(zero));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bn254_mul_invalid_inputs() {
        let mut k = [0u8; 32];
        k[31] = 3;

        // Not on curve
        let mut bad = [0u8; 64];
        bad[31] = 1;
        bad[63] = 1;
        let (ours, reference) = g1_mul_both(&bad, &k);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        // Non-canonical x = p + 1 (reduces to the generator's x)
        let mut sneaky = [0u8; 64];
        sneaky[..32].copy_from_slice(&BN254_FP_BE);
        sneaky[31] += 1;
        sneaky[63] = 2;
        let (ours, reference) = g1_mul_both(&sneaky, &k);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    // ---------- BN254 pairing ----------

    /// G1 generator (1, 2) ‖ G2 generator in EVM order (x_im, x_re, y_im, y_re).
    fn generator_pair() -> [u8; 192] {
        let mut pair = [0u8; 192];
        pair[31] = 1;
        pair[63] = 2;
        pair[64..192].copy_from_slice(&hex!(
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
            "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
            "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
            "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
        ));
        pair
    }

    #[test]
    fn bn254_pairing_eip197_vector() {
        // Standard two-pair vector: e(P1, Q1) · e(P2, Q2) == 1.
        let input = hex!(
            "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59"
            "3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"
            "209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7"
            "04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678"
            "2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d"
            "120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"
            "111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c"
            "2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411"
            "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
            "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
            "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
            "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
        );
        let (ours, reference) = pairing_both(&input);
        assert_eq!(ours, Ok(true));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bn254_pairing_false_empty_and_infinity_cases() {
        // Single (G1, G2) generator pair: e(G1, G2) != 1.
        let pair = generator_pair();
        let (ours, reference) = pairing_both(&pair);
        assert_eq!(ours, Ok(false));
        assert_eq!(ours, reference);

        // Empty input → true.
        let (ours, reference) = pairing_both(&[]);
        assert_eq!(ours, Ok(true));
        assert_eq!(ours, reference);

        // G1 = infinity → pair skipped → true.
        let mut inf_g1 = pair;
        inf_g1[..64].fill(0);
        let (ours, reference) = pairing_both(&inf_g1);
        assert_eq!(ours, Ok(true));
        assert_eq!(ours, reference);

        // G2 = infinity → pair skipped → true.
        let mut inf_g2 = pair;
        inf_g2[64..].fill(0);
        let (ours, reference) = pairing_both(&inf_g2);
        assert_eq!(ours, Ok(true));
        assert_eq!(ours, reference);

        // Generator pair + its negation pair: e(G1,G2) · e(-G1,G2) == 1.
        let mut neg_pair = pair;
        // -G1 = (1, p - 2)
        let mut y = BN254_FP_BE;
        y[31] -= 2;
        neg_pair[32..64].copy_from_slice(&y);
        let mut input = Vec::new();
        input.extend_from_slice(&pair);
        input.extend_from_slice(&neg_pair);
        let (ours, reference) = pairing_both(&input);
        assert_eq!(ours, Ok(true));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bn254_pairing_invalid_inputs() {
        let pair = generator_pair();

        // G1 not on curve, valid G2.
        let mut bad_g1 = pair;
        bad_g1[63] = 3; // (1, 3) not on curve
        let (ours, reference) = pairing_both(&bad_g1);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        // G2 tampered (x_im flipped) — not on the twist.
        let mut bad_g2 = pair;
        bad_g2[95] ^= 1;
        let (ours, reference) = pairing_both(&bad_g2);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        // THE canonicality case the upfront check exists for: G1 with
        // x = p + 1 (≡ generator mod p, so on-curve mod p) paired with
        // G2 = infinity. The reference rejects the non-canonical Fq even
        // though the pair would be skipped; zisklib alone would accept it.
        let mut sneaky = [0u8; 192];
        sneaky[..32].copy_from_slice(&BN254_FP_BE);
        sneaky[31] += 1; // x = p + 1
        sneaky[63] = 2; // y = 2
        let (ours, reference) = pairing_both(&sneaky);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        // Mirror case: non-canonical G2 coordinate with G1 = infinity.
        let mut sneaky_g2 = [0u8; 192];
        sneaky_g2[64..96].copy_from_slice(&BN254_FP_BE); // x_im = p
        let (ours, reference) = pairing_both(&sneaky_g2);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    // ---------- modexp ----------

    #[test]
    fn modexp_eip198_vectors() {
        // 3^(p-1) mod p = 1 for p = secp256k1's prime (EIP-198 example 1).
        let p = hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
        let p_minus_1 = hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e");
        let out = check_modexp(&[0x03], &p_minus_1, &p);
        let mut one = vec![0u8; 32];
        one[31] = 1;
        assert_eq!(out, one);

        // 0^(p-1) mod p = 0 (EIP-198 example 2 shape).
        let out = check_modexp(&[], &p_minus_1, &p);
        assert_eq!(out, vec![0u8; 32]);
    }

    #[test]
    fn modexp_zero_length_and_zero_value_operands() {
        let m5 = [0x05u8];

        // 0^0 = 1 (empty base, empty exp).
        assert_eq!(check_modexp(&[], &[], &m5), vec![1]);
        // x mod 1 = 0.
        assert_eq!(check_modexp(&[0x03], &[0x04], &[0x01]), vec![0]);
        // Zero modulus → all zeros (single and multi byte).
        assert_eq!(check_modexp(&[0x03], &[0x04], &[0x00]), vec![0]);
        assert_eq!(check_modexp(&[0x03], &[0x04], &[0x00, 0x00]), vec![0, 0]);
        // Zero-length modulus → empty output.
        assert_eq!(check_modexp(&[0x03], &[0x04], &[]), Vec::<u8>::new());
        // Zero exponent → 1.
        assert_eq!(check_modexp(&[0x03], &[], &m5), vec![1]);
        assert_eq!(check_modexp(&[0x03], &[0x00, 0x00], &m5), vec![1]);
        // Base 1.
        assert_eq!(check_modexp(&[0x01], &[0xff; 8], &m5), vec![1]);
        // 3^4 mod 5 = 1; 3^3 mod 5 = 2.
        assert_eq!(check_modexp(&[0x03], &[0x04], &m5), vec![1]);
        assert_eq!(check_modexp(&[0x03], &[0x03], &m5), vec![2]);
    }

    #[test]
    fn modexp_padding_and_leading_zero_shapes() {
        // Leading zeros in every operand; result must be left-padded to
        // the full (unstripped) modulus length.
        let base = hex!("0000000000000003");
        let exp = hex!("000000000000000000000002");
        let modulus = hex!("00000000000000000000000000000005");
        assert_eq!(
            check_modexp(&base, &exp, &modulus),
            hex!("00000000000000000000000000000004").to_vec()
        );

        // Base larger than modulus (reduction path).
        check_modexp(&hex!("ffffffffffffffffffffffffffffffff"), &[0x02], &[0x07]);

        // Modulus with a long zero prefix but multi-limb value.
        let modulus = hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        check_modexp(&[0xa7; 48], &[0x63; 5], &modulus);
    }

    #[test]
    fn modexp_multi_limb_operands_match_reference() {
        // Deterministic patterned operands across limb-boundary sizes,
        // including >256-bit (long-modulus path) and 33-byte exponents.
        for (bl, el, ml) in [
            (32usize, 32usize, 32usize),
            (33, 33, 33),
            (64, 33, 64),
            (96, 5, 96),
            (128, 16, 128),
            (17, 40, 31),
            (200, 8, 100),
        ] {
            let base: Vec<u8> = (0..bl).map(|i| (i * 71 + 13) as u8).collect();
            let exp: Vec<u8> = (0..el).map(|i| (i * 29 + 3) as u8).collect();
            let mut modulus: Vec<u8> = (0..ml).map(|i| (i * 83 + 57) as u8).collect();
            // Ensure odd, nonzero modulus for variety (not required).
            *modulus.last_mut().unwrap() |= 1;
            check_modexp(&base, &exp, &modulus);
        }
    }

    // ---------- secp256r1 ----------

    /// RIP-7212 reference test vector (valid signature).
    fn p256_vector() -> ([u8; 32], [u8; 64], [u8; 64]) {
        let msg = hex!("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4d");
        let sig = hex!(
            "a73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac"
            "36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d60"
        );
        let pk = hex!(
            "4aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff3"
            "7618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e"
        );
        (msg, sig, pk)
    }

    #[test]
    fn p256_rip7212_vector_and_tampering() {
        let (msg, sig, pk) = p256_vector();
        assert!(check_p256(&msg, &sig, &pk));

        // Any single tamper must flip to invalid.
        let mut bad_msg = msg;
        bad_msg[31] ^= 1;
        assert!(!check_p256(&bad_msg, &sig, &pk));

        let mut bad_sig = sig;
        bad_sig[63] ^= 1;
        assert!(!check_p256(&msg, &bad_sig, &pk));

        let mut bad_pk = pk;
        bad_pk[63] ^= 1; // y perturbed → off curve
        assert!(!check_p256(&msg, &sig, &bad_pk));
    }

    #[test]
    fn p256_high_s_is_accepted() {
        // RIP-7212 accepts both s and n - s (no low-s malleability rule).
        let (msg, sig, pk) = p256_vector();
        let mut mirrored = sig;
        // s' = n - s (big-endian subtraction; s < n so no final borrow).
        let mut borrow = 0u16;
        for i in (0..32).rev() {
            let n_i = P256_N_BE[i] as i16;
            let s_i = sig[32 + i] as i16;
            let mut d = n_i - s_i - borrow as i16;
            borrow = if d < 0 {
                d += 256;
                1
            } else {
                0
            };
            mirrored[32 + i] = d as u8;
        }
        assert_eq!(borrow, 0);
        assert!(check_p256(&msg, &mirrored, &pk));
    }

    /// The two corpus round-2 divergence vectors (osaka_eip7951 dumps
    /// 000019/000259 and 000241/000426, two batch cases each): valid
    /// signatures under public keys with x = 0 — the points (0, ±√b),
    /// reachable only by crafted keys. zisklib's fcall hint implementation
    /// corrupts the hinted R for such keys (its (0,0) infinity sentinel
    /// collides with legitimate x = 0 points in its curve-add), so the hook
    /// routes them to the software reference path; these pins fail with the
    /// pure zisklib path.
    fn p256_zero_x_vectors() -> [([u8; 32], [u8; 64], [u8; 64]); 2] {
        [
            (
                hex!("f98a88895cb0866c5bad58cf03000ddf9d21cb9407892ff54d637e6a046afbb3"),
                hex!(
                    "81dc074973d3222f3930981ad98d022517c91063ffb83cfd620e29b86dc30a8f"
                    "365e4cd085617a265765062a2d9954ed86309dfa33cf5ae1464fe119419fc34a"
                ),
                hex!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                    "99b7a386f1d07c29dbcc42a27b5f9449abe3d50de25178e8d7407a95e8b06c0b"
                ),
            ),
            (
                hex!("c3d3be9eb3577f217ae0ab360529a30b18adc751aec886328593d7d6fe042809"),
                hex!(
                    "3a4e97b44cbf88b90e6205a45ba957e520f63f3c6072b53c244653278a1819d8"
                    "6a184aa037688a5ebd25081fd2c0b10bb64fa558b671bd81955ca86e09d9d722"
                ),
                hex!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                    "66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4"
                ),
            ),
        ]
    }

    #[test]
    fn p256_zero_x_pubkey_vectors_match_reference() {
        let [(msg_a, sig_a, pk_a), (msg_b, sig_b, pk_b)] = p256_zero_x_vectors();

        // Both corpus vectors are VALID signatures.
        assert!(check_p256(&msg_a, &sig_a, &pk_a));
        assert!(check_p256(&msg_b, &sig_b, &pk_b));

        // Tampering must still reject through the same (software) path.
        let mut bad_sig = sig_a;
        bad_sig[63] ^= 1;
        assert!(!check_p256(&msg_a, &bad_sig, &pk_a));
        let mut bad_msg = msg_b;
        bad_msg[0] ^= 1;
        assert!(!check_p256(&bad_msg, &sig_b, &pk_b));

        // Cross-key: a's signature is invalid under b's key.
        assert!(!check_p256(&msg_a, &sig_a, &pk_b));
    }

    /// Tripwire pinning the UPSTREAM defect that motivates the x = 0
    /// software route in `secp256r1_verify`: zisklib's fcall hint (shared
    /// verbatim by native runs, ziskemu, and the prover via the fcall
    /// proxy) mis-computes R for x = 0 public keys, and the sound equation
    /// check then rejects the valid signature. If a ziskos bump makes this
    /// test FAIL, the upstream bug is fixed and the workaround branch (and
    /// this tripwire) can be dropped.
    #[test]
    fn p256_zero_x_pubkey_zisklib_hint_defect_tripwire() {
        let [(msg, sig, pk), _] = p256_zero_x_vectors();
        let z = be_bytes_to_u64_le_4(&msg);
        let r = be_bytes_to_u64_le_4(sig[..32].try_into().unwrap());
        let s = be_bytes_to_u64_le_4(sig[32..].try_into().unwrap());
        let x = be_bytes_to_u64_le_4(pk[..32].try_into().unwrap());
        let y = be_bytes_to_u64_le_4(pk[32..].try_into().unwrap());
        let pk_limbs = [x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]];
        assert!(
            !zisklib::ecdsa_verify_secp256r1(&pk_limbs, &z, &r, &s),
            "zisklib now verifies x = 0 public keys correctly — drop the \
             software route in secp256r1_verify and this tripwire"
        );
    }

    #[test]
    fn p256_signature_range_and_pk_validation() {
        let (msg, sig, pk) = p256_vector();

        // r = 0 and s = 0 are invalid.
        let mut r0 = sig;
        r0[..32].fill(0);
        assert!(!check_p256(&msg, &r0, &pk));
        let mut s0 = sig;
        s0[32..].fill(0);
        assert!(!check_p256(&msg, &s0, &pk));

        // r = n and s = n are out of range.
        let mut rn = sig;
        rn[..32].copy_from_slice(&P256_N_BE);
        assert!(!check_p256(&msg, &rn, &pk));
        let mut sn = sig;
        sn[32..].copy_from_slice(&P256_N_BE);
        assert!(!check_p256(&msg, &sn, &pk));

        // pk = (0, 0) (would-be identity encoding) is invalid.
        assert!(!check_p256(&msg, &sig, &[0u8; 64]));

        // pk with x >= p (non-canonical) is invalid: x = p.
        let p256_p = hex!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        let mut bad_pk = pk;
        bad_pk[..32].copy_from_slice(&p256_p);
        assert!(!check_p256(&msg, &sig, &bad_pk));
    }
}
