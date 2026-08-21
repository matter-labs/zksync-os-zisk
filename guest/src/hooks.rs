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
//! - `blake2b_compress`: RFC 7693 compression function F; updates `h` in place.
//! - `verify_kzg_proof`: EIP-4844 point evaluation; true = the proof holds.
//! - `bls12_381_*`: EIP-2537 semantics. Points are big-endian coordinate
//!   strings (G1 = x ‖ y, 48 bytes each; G2 = x_c0 ‖ x_c1 ‖ y_c0 ‖ y_c1),
//!   infinity = all zeros; MSM pairs append a 32-byte big-endian scalar.
//!   Return 0 = success, 1 = success-infinity (pairing check: 1 = product is
//!   not one), 2 and above = validation error (any error halts the
//!   precompile, exactly like the reference's parse errors).

use ziskos::zisklib;

/// BN254 base-field modulus p, big-endian:
/// 21888242871839275222246405745257275088696311157297823662689037894645226208583.
const BN254_FP_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
    0xfd, 0x47,
];

/// BLS12-381 base-field modulus p, big-endian:
/// 4002409555221667393417789825735904156556882819939007885332058136124031650490
/// 837864442687629129015664037894272559787.
const BLS12_381_FP_BE: [u8; 48] = [
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
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

/// RFC 7693 BLAKE2b compression function F, the core of the EIP-152
/// precompile (0x09).
///
/// Backed by the ZiSK `blake2b_round` syscall via `zisklib::blake2b_compress`,
/// which implements the round schedule and the final `h ^= v_lo ^ v_hi` fold
/// exactly as the reference does.
#[inline]
pub fn blake2b_compress(rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
    zisklib::blake2b_compress(rounds, h, m, t, f);
}

/// EIP-4844 KZG point evaluation for the `pointEvaluation` precompile (0x0a).
///
/// `z`/`y` are 32-byte big-endian scalars, `commitment`/`proof` are 48-byte
/// compressed G1 points. Returns true iff the proof holds for the trusted
/// setup that zisklib embeds (the Ethereum mainnet ceremony's τ·G2, the same
/// setup the reference's arkworks backend loads).
///
/// EXCEPTION — a commitment or a proof that decodes to a point of cofactor
/// order (see [`bls12_381_g1_order_divides_cofactor`]): zisklib holds both
/// points to the subgroup check that divides by zero on such a point. The
/// caller controls both, and 48 zero bytes with the compression flag decode
/// straight to the 3-torsion, so the class is one crafted blob call away.
/// A point of cofactor order lies outside G1, which is the verdict false,
/// and the reference rejects it as well.
pub fn verify_kzg_proof(
    z: &[u8; 32],
    y: &[u8; 32],
    commitment: &[u8; 48],
    proof: &[u8; 48],
) -> bool {
    if bls12_381_compressed_g1_order_divides_cofactor(commitment)
        || bls12_381_compressed_g1_order_divides_cofactor(proof)
    {
        return false;
    }
    zisklib::verify_kzg_proof(z, y, commitment, proof)
}

/// EIP-2537 BLS12-381 G1 addition (precompile 0x0b).
///
/// zisklib validates coordinate canonicality and curve membership and skips
/// the subgroup check, which is the exact G1ADD rule.
pub fn bls12_381_g1_add(a: &[u8; 96], b: &[u8; 96], out: &mut [u8; 96]) -> u8 {
    let a = zisklib::g1_bytes_be_to_u64_le_bls12_381(a);
    let b = zisklib::g1_bytes_be_to_u64_le_bls12_381(b);
    match zisklib::add_complete_bls12_381(&a, &b) {
        Ok(sum) if sum == [0u64; 12] => {
            out.fill(0);
            1
        }
        Ok(sum) => {
            zisklib::g1_u64_le_to_bytes_be_bls12_381(&sum, out);
            0
        }
        Err(code) => code,
    }
}

/// EIP-2537 BLS12-381 G1 multi-scalar multiplication (precompile 0x0c).
///
/// `pairs` is `n` × 128 bytes (96-byte point ‖ 32-byte scalar).
///
/// EXCEPTION — a call that holds a pair whose point is not the identity and
/// whose scalar reduces to zero mod the subgroup order r: zisklib's
/// `msm_complete_bls12_381` drops such a pair BEFORE it validates the point,
/// while the reference validates every point and drops the zero-scalar pairs
/// only after that. An invalid point next to such a scalar therefore halts
/// the reference where zisklib alone returns a value. Route that call to
/// REVM's software reference (`DefaultCrypto`), bit-identical to the native
/// side of the equivalence check by construction; every other call keeps the
/// accelerated path, and a zero-mod-r scalar contributes nothing, so real
/// traffic rarely carries one. The route links REVM's arkworks BLS12-381
/// backend, which costs about 160 KiB of guest ROM and no cycles outside the
/// corner case. Drop this branch when upstream validates the point before it
/// drops the pair (see the tripwire test below).
///
/// EXCEPTION — a call that holds a point of cofactor order (see
/// [`bls12_381_g1_order_divides_cofactor`]): zisklib's subgroup check divides
/// by zero on such a point, and the division sits behind a non-unwinding
/// `extern "C"` shim, so the guest and the prover witness generator both
/// raise SIGABRT. Route that call to the software reference as well. Every
/// such point is outside G1, so the call halts either way; the software
/// route only makes the guest reach that verdict. Drop this branch when
/// upstream guards the exceptional cases (see the tripwire test below).
pub fn bls12_381_g1_msm(pairs: &[u8], out: &mut [u8; 96]) -> u8 {
    debug_assert!(pairs.len().is_multiple_of(128));
    let mut points: Vec<[u64; 12]> = Vec::with_capacity(pairs.len() / 128);
    let mut scalars: Vec<[u64; 4]> = Vec::with_capacity(pairs.len() / 128);
    for pair in pairs.chunks_exact(128) {
        let point: &[u8; 96] = pair[..96].try_into().unwrap();
        let scalar: &[u8; 32] = pair[96..].try_into().unwrap();
        points.push(zisklib::g1_bytes_be_to_u64_le_bls12_381(point));
        scalars.push(zisklib::scalar_bytes_be_to_u64_le_bls12_381(scalar));
    }

    if points
        .iter()
        .zip(scalars.iter())
        .any(|(point, scalar)| *point != [0u64; 12] && msm_scalar_is_zero_mod_r(scalar))
    {
        return bls12_381_g1_msm_software(pairs, out);
    }

    if pairs
        .chunks_exact(128)
        .any(|pair| bls12_381_g1_order_divides_cofactor(pair[..96].try_into().unwrap()))
    {
        return bls12_381_g1_msm_software(pairs, out);
    }

    match zisklib::msm_complete_bls12_381(&points, &scalars) {
        Ok(sum) if sum == [0u64; 12] => {
            out.fill(0);
            1
        }
        Ok(sum) => {
            zisklib::g1_u64_le_to_bytes_be_bls12_381(&sum, out);
            0
        }
        Err(code) => code,
    }
}

/// EIP-2537 BLS12-381 G2 addition (precompile 0x0d).
pub fn bls12_381_g2_add(a: &[u8; 192], b: &[u8; 192], out: &mut [u8; 192]) -> u8 {
    let a = zisklib::g2_bytes_be_to_u64_le_bls12_381(a);
    let b = zisklib::g2_bytes_be_to_u64_le_bls12_381(b);
    match zisklib::add_complete_twist_bls12_381(&a, &b) {
        Ok(sum) if sum == [0u64; 24] => {
            out.fill(0);
            1
        }
        Ok(sum) => {
            zisklib::g2_u64_le_to_bytes_be_bls12_381(&sum, out);
            0
        }
        Err(code) => code,
    }
}

/// EIP-2537 BLS12-381 G2 multi-scalar multiplication (precompile 0x0e).
///
/// `pairs` is `n` × 224 bytes (192-byte point ‖ 32-byte scalar). The software
/// route is the G2 twin of the one in [`bls12_381_g1_msm`], for the same
/// upstream drop-before-validation divergence. The twist arithmetic inverts
/// through zisklib's `inv_fp2_bls12_381`, which maps zero to zero, so an
/// identity intermediate in the G2 subgroup check divides nothing and needs
/// no counterpart of the cofactor screen.
pub fn bls12_381_g2_msm(pairs: &[u8], out: &mut [u8; 192]) -> u8 {
    debug_assert!(pairs.len().is_multiple_of(224));
    let mut points: Vec<[u64; 24]> = Vec::with_capacity(pairs.len() / 224);
    let mut scalars: Vec<[u64; 4]> = Vec::with_capacity(pairs.len() / 224);
    for pair in pairs.chunks_exact(224) {
        let point: &[u8; 192] = pair[..192].try_into().unwrap();
        let scalar: &[u8; 32] = pair[192..].try_into().unwrap();
        points.push(zisklib::g2_bytes_be_to_u64_le_bls12_381(point));
        scalars.push(zisklib::scalar_bytes_be_to_u64_le_bls12_381(scalar));
    }

    if points
        .iter()
        .zip(scalars.iter())
        .any(|(point, scalar)| *point != [0u64; 24] && msm_scalar_is_zero_mod_r(scalar))
    {
        return bls12_381_g2_msm_software(pairs, out);
    }

    match zisklib::msm_complete_twist_bls12_381(&points, &scalars) {
        Ok(sum) if sum == [0u64; 24] => {
            out.fill(0);
            1
        }
        Ok(sum) => {
            zisklib::g2_u64_le_to_bytes_be_bls12_381(&sum, out);
            0
        }
        Err(code) => code,
    }
}

/// EIP-2537 BLS12-381 pairing check (precompile 0x0f).
///
/// `pairs` is `n` × 288 bytes (96-byte G1 ‖ 192-byte G2). Returns 0 when the
/// product of pairings is one, 1 when it is not.
///
/// EXCEPTION — a call that holds a G1 point of cofactor order (see
/// [`bls12_381_g1_order_divides_cofactor`]): the G1 subgroup check that
/// validates every pair divides by zero on such a point, exactly as in
/// [`bls12_381_g1_msm`], so the call takes the software reference.
pub fn bls12_381_pairing_check(pairs: &[u8]) -> u8 {
    debug_assert!(pairs.len().is_multiple_of(288));
    if pairs
        .chunks_exact(288)
        .any(|pair| bls12_381_g1_order_divides_cofactor(pair[..96].try_into().unwrap()))
    {
        return bls12_381_pairing_check_software(pairs);
    }

    let mut g1_points: Vec<[u64; 12]> = Vec::with_capacity(pairs.len() / 288);
    let mut g2_points: Vec<[u64; 24]> = Vec::with_capacity(pairs.len() / 288);
    for pair in pairs.chunks_exact(288) {
        let g1: &[u8; 96] = pair[..96].try_into().unwrap();
        let g2: &[u8; 192] = pair[96..].try_into().unwrap();
        g1_points.push(zisklib::g1_bytes_be_to_u64_le_bls12_381(g1));
        g2_points.push(zisklib::g2_bytes_be_to_u64_le_bls12_381(g2));
    }

    match zisklib::pairing_check_bls12_381(&g1_points, &g2_points) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(code) => code,
    }
}

/// EIP-2537 BLS12-381 map Fp to G1 (precompile 0x10), through the software
/// reference (`DefaultCrypto`).
///
/// zisklib clears the cofactor with the raw curve syscalls, which have no
/// identity encoding. A field element whose isogeny image is the identity —
/// the kernel values the EIP-2537 fixtures carry, and the elements that map
/// to infinity — therefore divides by zero behind a non-unwinding
/// `extern "C"` shim, which raises SIGABRT in the guest and in the prover
/// witness generator. A kernel element is much harder to detect in the input
/// than a small-order point, and these two precompiles carry the least
/// traffic of the EIP-2537 set, so the whole hook takes the software route.
/// Restore the accelerated path when upstream clears the cofactor with the
/// complete formulas (see the tripwire test below).
pub fn bls12_381_fp_to_g1(fp: &[u8; 48], out: &mut [u8; 96]) -> u8 {
    use revm::precompile::{Crypto, DefaultCrypto};
    match DefaultCrypto.bls12_381_fp_to_g1(fp) {
        Ok(point) => {
            out.copy_from_slice(&point);
            0
        }
        Err(_) => 1,
    }
}

/// EIP-2537 BLS12-381 map Fp2 to G2 (precompile 0x11), through the software
/// reference (`DefaultCrypto`).
///
/// `fp2` is c0 ‖ c1, each a 48-byte big-endian field element. The twist
/// counterpart of the cofactor clearing in [`bls12_381_fp_to_g1`] divides
/// nothing, because zisklib's `inv_fp2_bls12_381` maps zero to zero. Its
/// addition formula returns a value off the curve when one operand is the
/// identity and the other is not, which is the shape an isogeny image of
/// small order takes, so the G2 map holds to the software route for that
/// class.
pub fn bls12_381_fp2_to_g2(fp2: &[u8; 96], out: &mut [u8; 192]) -> u8 {
    use revm::precompile::{Crypto, DefaultCrypto};
    match DefaultCrypto.bls12_381_fp2_to_g2((
        fp2[..48].try_into().unwrap(),
        fp2[48..].try_into().unwrap(),
    )) {
        Ok(point) => {
            out.copy_from_slice(&point);
            0
        }
        Err(_) => 1,
    }
}

/// True when an MSM scalar reduces to zero mod the BLS12-381 subgroup order
/// r, i.e. it is one of 0, r and 2r — the drop condition of zisklib's MSM.
/// The reduction is part of the condition: r and 2r are dropped exactly like
/// the literal zero.
fn msm_scalar_is_zero_mod_r(scalar: &[u64; 4]) -> bool {
    zisklib::is_zero(&zisklib::reduce_fr_bls12_381(scalar))
}

/// BLS12-381 G1 cofactor h = (x-1)²/3, little-endian 64-bit limbs.
const BLS12_381_G1_COFACTOR: [u64; 2] = [0x8c00_aaab_0000_aaab, 0x396c_8c00_5555_e156];

/// True when the EIP-2537 G1 point `point` is a curve point whose order
/// divides the G1 cofactor h — the exact class of G1 inputs that drives
/// zisklib's subgroup check into a division by zero.
///
/// `is_on_subgroup_bls12_381` walks 3·σ(P) through a 126-step ladder of raw
/// curve syscalls. Those syscalls carry no identity encoding, so the ladder
/// divides by zero as soon as an intermediate [n]·3σ(P) reaches 𝒪. Every
/// such intermediate holds |n| < 2¹²⁷, far below the subgroup order r, and
/// the curve has no point of order two, so the ladder reaches 𝒪 exactly when
/// the order of P divides h. The identity, a coordinate outside the field
/// and a point off the curve answer false: zisklib rejects each of them
/// before the ladder runs.
fn bls12_381_g1_order_divides_cofactor(point: &[u8; 96]) -> bool {
    if point.iter().all(|&b| b == 0)
        || !fp_is_canonical(&point[..48])
        || !fp_is_canonical(&point[48..])
    {
        return false;
    }
    let p = zisklib::g1_bytes_be_to_u64_le_bls12_381(point);
    zisklib::is_on_curve_bls12_381(&p) && bls12_381_g1_cofactor_multiple_is_identity(&p)
}

/// [h]`p` == 𝒪 for a BLS12-381 curve point `p` other than the identity.
///
/// The ladder runs on the accelerated point operations with the identity
/// cases held outside them: zisklib's `add_bls12_381` covers the equal-x
/// cases itself, and both operations need a non-identity input.
fn bls12_381_g1_cofactor_multiple_is_identity(p: &[u64; 12]) -> bool {
    const IDENTITY: [u64; 12] = [0u64; 12];

    let mut acc = IDENTITY;
    for bit in (0..126).rev() {
        if acc != IDENTITY {
            acc = zisklib::dbl_bls12_381(&acc);
        }
        if (BLS12_381_G1_COFACTOR[bit / 64] >> (bit % 64)) & 1 == 1 {
            acc = if acc == IDENTITY {
                *p
            } else {
                zisklib::add_bls12_381(&acc, p)
            };
        }
    }
    acc == IDENTITY
}

/// True when the compressed G1 point `compressed` decodes to a point whose
/// order divides the G1 cofactor (see
/// [`bls12_381_g1_order_divides_cofactor`]). The infinity encoding and every
/// encoding zisklib rejects answer false: neither reaches the subgroup
/// check.
fn bls12_381_compressed_g1_order_divides_cofactor(compressed: &[u8; 48]) -> bool {
    match zisklib::decompress_bls12_381(compressed) {
        Ok(p) if p != [0u64; 12] => bls12_381_g1_cofactor_multiple_is_identity(&p),
        _ => false,
    }
}

/// [`bls12_381_g1_msm`] through the software reference. The error codes are
/// the ones the accelerated path returns for the same failure classes.
fn bls12_381_g1_msm_software(pairs: &[u8], out: &mut [u8; 96]) -> u8 {
    use revm::precompile::{bls12_381::G1PointScalar, Crypto, DefaultCrypto, PrecompileHalt};
    let mut it = pairs
        .chunks_exact(128)
        .map(|pair| -> Result<G1PointScalar, PrecompileHalt> {
            Ok((
                (
                    pair[..48].try_into().unwrap(),
                    pair[48..96].try_into().unwrap(),
                ),
                pair[96..].try_into().unwrap(),
            ))
        });
    match DefaultCrypto.bls12_381_g1_msm(&mut it) {
        Ok(sum) if sum == [0u8; 96] => {
            out.fill(0);
            1
        }
        Ok(sum) => {
            out.copy_from_slice(&sum);
            0
        }
        Err(PrecompileHalt::Bls12381G1NotOnCurve) => 3,
        Err(PrecompileHalt::Bls12381G1NotInSubgroup) => 4,
        Err(_) => 2,
    }
}

/// G2 counterpart of [`bls12_381_g1_msm_software`].
fn bls12_381_g2_msm_software(pairs: &[u8], out: &mut [u8; 192]) -> u8 {
    use revm::precompile::{bls12_381::G2PointScalar, Crypto, DefaultCrypto, PrecompileHalt};
    let mut it = pairs
        .chunks_exact(224)
        .map(|pair| -> Result<G2PointScalar, PrecompileHalt> {
            Ok((
                (
                    pair[..48].try_into().unwrap(),
                    pair[48..96].try_into().unwrap(),
                    pair[96..144].try_into().unwrap(),
                    pair[144..192].try_into().unwrap(),
                ),
                pair[192..].try_into().unwrap(),
            ))
        });
    match DefaultCrypto.bls12_381_g2_msm(&mut it) {
        Ok(sum) if sum == [0u8; 192] => {
            out.fill(0);
            1
        }
        Ok(sum) => {
            out.copy_from_slice(&sum);
            0
        }
        Err(PrecompileHalt::Bls12381G2NotOnCurve) => 3,
        Err(PrecompileHalt::Bls12381G2NotInSubgroup) => 4,
        Err(_) => 2,
    }
}

/// [`bls12_381_pairing_check`] through the software reference. The error
/// codes are the ones the accelerated path returns for the same failure
/// classes.
fn bls12_381_pairing_check_software(pairs: &[u8]) -> u8 {
    use revm::precompile::{
        bls12_381::{G1Point, G2Point},
        Crypto, DefaultCrypto, PrecompileHalt,
    };
    let collected: Vec<(G1Point, G2Point)> = pairs
        .chunks_exact(288)
        .map(|pair| {
            (
                (
                    pair[..48].try_into().unwrap(),
                    pair[48..96].try_into().unwrap(),
                ),
                (
                    pair[96..144].try_into().unwrap(),
                    pair[144..192].try_into().unwrap(),
                    pair[192..240].try_into().unwrap(),
                    pair[240..].try_into().unwrap(),
                ),
            )
        })
        .collect();
    match DefaultCrypto.bls12_381_pairing_check(&collected) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(PrecompileHalt::Bls12381G1NotOnCurve) => 3,
        Err(PrecompileHalt::Bls12381G1NotInSubgroup) => 4,
        Err(PrecompileHalt::Bls12381G2NotOnCurve) => 6,
        Err(PrecompileHalt::Bls12381G2NotInSubgroup) => 7,
        Err(_) => 2,
    }
}

// ==================== conversion helpers ====================

/// A 32-byte big-endian field element is canonical iff it is < p.
#[inline]
fn fq_is_canonical(be: &[u8]) -> bool {
    debug_assert_eq!(be.len(), 32);
    be < &BN254_FP_BE[..]
}

/// A 48-byte big-endian BLS12-381 field element is canonical iff it is < p.
#[inline]
fn fp_is_canonical(be: &[u8]) -> bool {
    debug_assert_eq!(be.len(), 48);
    be < &BLS12_381_FP_BE[..]
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
    use revm::precompile::{
        bls12_381::{G1Point, G1PointScalar, G2Point, G2PointScalar},
        Crypto, DefaultCrypto,
    };

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

    // ---------- BLAKE2b ----------

    fn blake2b_both(
        rounds: u32,
        h: &[u64; 8],
        m: &[u64; 16],
        t: &[u64; 2],
        f: bool,
    ) -> ([u64; 8], [u64; 8]) {
        let mut ours = *h;
        blake2b_compress(rounds, &mut ours, m, t, f);
        let mut reference = *h;
        DefaultCrypto.blake2_compress(rounds, &mut reference, m, t, f);
        assert_eq!(ours, reference, "blake2b mismatch (rounds {rounds}, f {f})");
        (ours, reference)
    }

    #[test]
    fn blake2b_eip152_vector() {
        // EIP-152 vector 4: the "abc" digest state after one 12-round
        // compression of the BLAKE2b-512 initial state.
        let mut h = [
            0x6a09e667f3bcc908 ^ 0x0101_0040,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];
        let mut m = [0u64; 16];
        m[0] = u64::from_le_bytes(*b"abc\0\0\0\0\0");
        let (ours, _) = blake2b_both(12, &h, &m, &[3, 0], true);
        h = ours;
        let mut digest = [0u8; 64];
        for (i, word) in h.iter().enumerate() {
            digest[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            digest,
            hex!(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            )
        );
    }

    #[test]
    fn blake2b_matches_reference_across_round_counts_and_flags() {
        // Deterministic patterned state/message; the round count drives the
        // sigma schedule wrap-around (r % 10), so cover past one full cycle.
        let h: [u64; 8] = core::array::from_fn(|i| (i as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15));
        let m: [u64; 16] =
            core::array::from_fn(|i| (i as u64 + 7).wrapping_mul(0xc2b2ae3d27d4eb4f));
        for rounds in [0u32, 1, 9, 10, 11, 12, 25] {
            for f in [false, true] {
                blake2b_both(rounds, &h, &m, &[0x0123_4567, 0x89ab_cdef], f);
            }
        }
    }

    // ---------- KZG point evaluation ----------

    fn kzg_both(z: &[u8; 32], y: &[u8; 32], commitment: &[u8; 48], proof: &[u8; 48]) -> bool {
        let ours = verify_kzg_proof(z, y, commitment, proof);
        let reference = DefaultCrypto
            .verify_kzg_proof(z, y, commitment, proof)
            .is_ok();
        assert_eq!(ours, reference, "kzg verdict mismatch");
        ours
    }

    #[test]
    fn kzg_mainnet_vector_and_tampering() {
        // c-kzg-4844 `verify_kzg_proof_case_correct_proof_4_4` (mainnet
        // trusted setup), the vector REVM's own precompile test pins.
        let z = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
        let y = hex!("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9");
        let commitment = hex!(
            "8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca2"
            "5f26936857bc3a7c2539ea8ec3a952b7"
        );
        let proof = hex!(
            "a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc216074"
            "4faf0070725e00b60ad9a026a15b1a8c"
        );
        assert!(kzg_both(&z, &y, &commitment, &proof));

        // Any single tamper must flip to invalid.
        let mut bad_y = y;
        bad_y[31] ^= 1;
        assert!(!kzg_both(&z, &bad_y, &commitment, &proof));
        let mut bad_proof = proof;
        bad_proof[47] ^= 1;
        assert!(!kzg_both(&z, &y, &commitment, &bad_proof));
    }

    /// A compressed G1 point whose x is zero decodes to the σ-fixed
    /// 3-torsion, so the compression flag alone puts a point of cofactor
    /// order in the commitment or the proof field. Both sides reject it.
    /// These pins abort with the pure zisklib path.
    #[test]
    fn kzg_cofactor_order_commitment_and_proof_match_reference() {
        let mut three_torsion = [0u8; 48];
        three_torsion[0] = 0x80; // compression flag, x = 0
        assert!(bls12_381_compressed_g1_order_divides_cofactor(
            &three_torsion
        ));

        let z = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
        let y = hex!("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9");
        let commitment = hex!(
            "8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca2"
            "5f26936857bc3a7c2539ea8ec3a952b7"
        );
        let proof = hex!(
            "a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc216074"
            "4faf0070725e00b60ad9a026a15b1a8c"
        );
        assert!(!kzg_both(&z, &y, &three_torsion, &proof));
        assert!(!kzg_both(&z, &y, &commitment, &three_torsion));
    }

    #[test]
    fn kzg_infinity_commitment_cases() {
        // Commitment and proof both the compressed point at infinity: the
        // zero polynomial evaluates to zero everywhere.
        let mut infinity = [0u8; 48];
        infinity[0] = 0xc0; // compressed-point encoding of the identity
        let z = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
        assert!(kzg_both(&z, &[0u8; 32], &infinity, &infinity));

        // Same commitment with a non-zero claimed evaluation must fail.
        let y = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        assert!(!kzg_both(&[0u8; 32], &y, &infinity, &infinity));
    }

    // ---------- BLS12-381 ----------

    /// A valid G1 subgroup point, built through the reference map-to-curve so
    /// the test needs no hardcoded generator.
    fn bls_g1(seed: u8) -> [u8; 96] {
        let mut fp = [0u8; 48];
        fp[47] = seed;
        DefaultCrypto.bls12_381_fp_to_g1(&fp).unwrap()
    }

    /// A valid G2 subgroup point (see [`bls_g1`]).
    fn bls_g2(seed: u8) -> [u8; 192] {
        let mut c0 = [0u8; 48];
        c0[47] = seed;
        DefaultCrypto.bls12_381_fp2_to_g2((c0, [0u8; 48])).unwrap()
    }

    /// Negate a G1 point: -(x, y) = (x, p - y).
    fn bls_g1_neg(p: &[u8; 96]) -> [u8; 96] {
        let mut out = *p;
        out[48..].copy_from_slice(&fp_neg(p[48..].try_into().unwrap()));
        out
    }

    /// p - x over the BLS12-381 base field, big-endian (x is non-zero).
    fn fp_neg(x: &[u8; 48]) -> [u8; 48] {
        let mut out = [0u8; 48];
        let mut borrow = 0i16;
        for i in (0..48).rev() {
            let mut d = BLS12_381_FP_BE[i] as i16 - x[i] as i16 - borrow;
            borrow = if d < 0 {
                d += 256;
                1
            } else {
                0
            };
            out[i] = d as u8;
        }
        assert_eq!(borrow, 0);
        out
    }

    fn split_g1(p: &[u8; 96]) -> G1Point {
        (p[..48].try_into().unwrap(), p[48..].try_into().unwrap())
    }

    fn split_g2(p: &[u8; 192]) -> G2Point {
        (
            p[..48].try_into().unwrap(),
            p[48..96].try_into().unwrap(),
            p[96..144].try_into().unwrap(),
            p[144..].try_into().unwrap(),
        )
    }

    fn bls_g1_add_both(a: &[u8; 96], b: &[u8; 96]) -> (Result<[u8; 96], ()>, Result<[u8; 96], ()>) {
        let mut out = [0u8; 96];
        let ours = match bls12_381_g1_add(a, b, &mut out) {
            0 | 1 => Ok(out),
            _ => Err(()),
        };
        let reference = DefaultCrypto
            .bls12_381_g1_add(split_g1(a), split_g1(b))
            .map_err(|_| ());
        (ours, reference)
    }

    fn bls_g2_add_both(
        a: &[u8; 192],
        b: &[u8; 192],
    ) -> (Result<[u8; 192], ()>, Result<[u8; 192], ()>) {
        let mut out = [0u8; 192];
        let ours = match bls12_381_g2_add(a, b, &mut out) {
            0 | 1 => Ok(out),
            _ => Err(()),
        };
        let reference = DefaultCrypto
            .bls12_381_g2_add(split_g2(a), split_g2(b))
            .map_err(|_| ());
        (ours, reference)
    }

    fn bls_g1_msm_both(
        pairs: &[([u8; 96], [u8; 32])],
    ) -> (Result<[u8; 96], ()>, Result<[u8; 96], ()>) {
        let mut flat = Vec::new();
        for (point, scalar) in pairs {
            flat.extend_from_slice(point);
            flat.extend_from_slice(scalar);
        }
        let mut out = [0u8; 96];
        let ours = match bls12_381_g1_msm(&flat, &mut out) {
            0 | 1 => Ok(out),
            _ => Err(()),
        };
        let collected: Vec<G1PointScalar> = pairs.iter().map(|(p, s)| (split_g1(p), *s)).collect();
        let mut it = collected.into_iter().map(Ok);
        let reference = DefaultCrypto.bls12_381_g1_msm(&mut it).map_err(|_| ());
        (ours, reference)
    }

    fn bls_g2_msm_both(
        pairs: &[([u8; 192], [u8; 32])],
    ) -> (Result<[u8; 192], ()>, Result<[u8; 192], ()>) {
        let mut flat = Vec::new();
        for (point, scalar) in pairs {
            flat.extend_from_slice(point);
            flat.extend_from_slice(scalar);
        }
        let mut out = [0u8; 192];
        let ours = match bls12_381_g2_msm(&flat, &mut out) {
            0 | 1 => Ok(out),
            _ => Err(()),
        };
        let collected: Vec<G2PointScalar> = pairs.iter().map(|(p, s)| (split_g2(p), *s)).collect();
        let mut it = collected.into_iter().map(Ok);
        let reference = DefaultCrypto.bls12_381_g2_msm(&mut it).map_err(|_| ());
        (ours, reference)
    }

    fn bls_pairing_both(pairs: &[([u8; 96], [u8; 192])]) -> (Result<bool, ()>, Result<bool, ()>) {
        let mut flat = Vec::new();
        for (g1, g2) in pairs {
            flat.extend_from_slice(g1);
            flat.extend_from_slice(g2);
        }
        let ours = match bls12_381_pairing_check(&flat) {
            0 => Ok(true),
            1 => Ok(false),
            _ => Err(()),
        };
        let ref_pairs: Vec<(G1Point, G2Point)> = pairs
            .iter()
            .map(|(g1, g2)| (split_g1(g1), split_g2(g2)))
            .collect();
        let reference = DefaultCrypto
            .bls12_381_pairing_check(&ref_pairs)
            .map_err(|_| ());
        (ours, reference)
    }

    fn scalar(v: u64) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[24..].copy_from_slice(&v.to_be_bytes());
        s
    }

    /// BLS12-381 subgroup order r, big-endian.
    const BLS12_381_FR_BE: [u8; 32] =
        hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

    #[test]
    fn bls_g1_add_matches_reference() {
        let p = bls_g1(1);
        let q = bls_g1(2);
        let zero = [0u8; 96];

        for (a, b) in [
            (p, q),
            (p, p),
            (p, zero),
            (zero, p),
            (zero, zero),
            (p, bls_g1_neg(&p)),
        ] {
            let (ours, reference) = bls_g1_add_both(&a, &b);
            assert!(ours.is_ok());
            assert_eq!(ours, reference);
        }

        // Off-curve and non-canonical inputs must halt on both sides.
        let mut off_curve = p;
        off_curve[95] ^= 1;
        let (ours, reference) = bls_g1_add_both(&off_curve, &q);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        let mut non_canonical = p;
        non_canonical[..48].copy_from_slice(&BLS12_381_FP_BE);
        let (ours, reference) = bls_g1_add_both(&non_canonical, &q);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bls_g2_add_matches_reference() {
        let p = bls_g2(1);
        let q = bls_g2(2);
        let zero = [0u8; 192];

        for (a, b) in [(p, q), (p, p), (p, zero), (zero, p), (zero, zero)] {
            let (ours, reference) = bls_g2_add_both(&a, &b);
            assert!(ours.is_ok());
            assert_eq!(ours, reference);
        }

        let mut off_curve = p;
        off_curve[191] ^= 1;
        let (ours, reference) = bls_g2_add_both(&off_curve, &q);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        let mut non_canonical = p;
        non_canonical[48..96].copy_from_slice(&BLS12_381_FP_BE);
        let (ours, reference) = bls_g2_add_both(&non_canonical, &q);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bls_g1_msm_matches_reference() {
        let p = bls_g1(3);
        let q = bls_g1(5);

        for pairs in [
            vec![(p, scalar(1))],
            vec![(p, scalar(2))],
            vec![(p, scalar(0))],
            vec![(p, BLS12_381_FR_BE)],
            vec![(p, [0xff; 32])],
            vec![(p, scalar(7)), (q, scalar(11))],
            vec![([0u8; 96], scalar(9)), (q, scalar(4))],
        ] {
            let (ours, reference) = bls_g1_msm_both(&pairs);
            assert!(ours.is_ok());
            assert_eq!(ours, reference);
        }

        // Off-curve point, non-zero scalar.
        let mut off_curve = p;
        off_curve[95] ^= 1;
        let (ours, reference) = bls_g1_msm_both(&[(off_curve, scalar(3))]);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    /// The reference validates every MSM point BEFORE it drops the pairs
    /// whose scalar is zero, so an invalid point halts the precompile even
    /// when its scalar contributes nothing. zisklib's MSM drops those pairs
    /// first, which is why the hook routes such a call to the software
    /// reference. A scalar equal to the subgroup order r covers the same drop
    /// through the reduction path. These pins fail with the pure zisklib path.
    #[test]
    fn bls_msm_invalid_point_with_zero_scalar_halts() {
        let mut off_curve_g1 = bls_g1(3);
        off_curve_g1[95] ^= 1;
        let mut non_canonical_g1 = bls_g1(3);
        non_canonical_g1[..48].copy_from_slice(&BLS12_381_FP_BE);

        for point in [off_curve_g1, non_canonical_g1] {
            for s in [scalar(0), BLS12_381_FR_BE] {
                let (ours, reference) = bls_g1_msm_both(&[(point, s), (bls_g1(5), scalar(2))]);
                assert_eq!(ours, Err(()), "G1 scalar {s:02x?}");
                assert_eq!(ours, reference);
            }
        }

        let mut off_curve_g2 = bls_g2(3);
        off_curve_g2[191] ^= 1;
        let mut non_canonical_g2 = bls_g2(3);
        non_canonical_g2[48..96].copy_from_slice(&BLS12_381_FP_BE);

        for point in [off_curve_g2, non_canonical_g2] {
            for s in [scalar(0), BLS12_381_FR_BE] {
                let (ours, reference) = bls_g2_msm_both(&[(point, s), (bls_g2(5), scalar(2))]);
                assert_eq!(ours, Err(()), "G2 scalar {s:02x?}");
                assert_eq!(ours, reference);
            }
        }
    }

    /// Tripwire pinning the UPSTREAM defect that motivates the software route
    /// in `bls12_381_g1_msm`: zisklib's `msm_complete_bls12_381` drops a pair
    /// whose scalar reduces to zero mod r before it validates the point, so
    /// it accepts an off-curve point that the reference rejects. If a ziskos
    /// bump makes this test FAIL, the upstream defect is fixed and the
    /// software route (and this tripwire) can be dropped.
    #[test]
    fn bls_g1_msm_dropped_pair_zisklib_defect_tripwire() {
        let mut off_curve = bls_g1(3);
        off_curve[95] ^= 1;
        let points = [zisklib::g1_bytes_be_to_u64_le_bls12_381(&off_curve)];
        for s in [scalar(0), BLS12_381_FR_BE] {
            let scalars = [zisklib::scalar_bytes_be_to_u64_le_bls12_381(&s)];
            assert_eq!(
                zisklib::msm_complete_bls12_381(&points, &scalars),
                Ok([0u64; 12]),
                "zisklib's G1 MSM validates the point of a dropped pair \
                 (scalar {s:02x?}) — drop the software route in \
                 bls12_381_g1_msm and this tripwire"
            );
        }
    }

    /// G2 counterpart of [`bls_g1_msm_dropped_pair_zisklib_defect_tripwire`].
    #[test]
    fn bls_g2_msm_dropped_pair_zisklib_defect_tripwire() {
        let mut off_curve = bls_g2(3);
        off_curve[191] ^= 1;
        let points = [zisklib::g2_bytes_be_to_u64_le_bls12_381(&off_curve)];
        for s in [scalar(0), BLS12_381_FR_BE] {
            let scalars = [zisklib::scalar_bytes_be_to_u64_le_bls12_381(&s)];
            assert_eq!(
                zisklib::msm_complete_twist_bls12_381(&points, &scalars),
                Ok([0u64; 24]),
                "zisklib's G2 MSM validates the point of a dropped pair \
                 (scalar {s:02x?}) — drop the software route in \
                 bls12_381_g2_msm and this tripwire"
            );
        }
    }

    /// G1 points whose order divides the cofactor h: the two σ-fixed
    /// 3-torsion points (0, ±2), which are the ones the EIP-2537 fixtures
    /// carry, and an 11-torsion point, which they do not.
    fn bls_g1_cofactor_order_points() -> [[u8; 96]; 3] {
        let mut three_torsion = [0u8; 96];
        three_torsion[95] = 2;
        let mut three_torsion_neg = three_torsion;
        three_torsion_neg[48..].copy_from_slice(&fp_neg(three_torsion[48..].try_into().unwrap()));
        let eleven_torsion = hex!(
            "19b3e2c8c6bbf59d3c326b531fc1e639d29200c28624ac604f251a12908c9b7f"
            "735318617f625954cc71cdf03229b1ef"
            "042fcc94d6c6440d3c0a01177616b72eb6972d90e36e88b5981a05a52ab48ce3"
            "e22fa88d10f6de85a7d386aad66c0ca8"
        );
        [three_torsion, three_torsion_neg, eleven_torsion]
    }

    /// A curve point outside G1 whose order carries the subgroup order r:
    /// G1ADD applies no subgroup rule, so it composes one from a G1 point
    /// and the 3-torsion.
    fn bls_g1_large_order_off_subgroup() -> [u8; 96] {
        let mut out = [0u8; 96];
        let [three_torsion, _, _] = bls_g1_cofactor_order_points();
        assert_eq!(bls12_381_g1_add(&bls_g1(3), &three_torsion, &mut out), 0);
        out
    }

    /// The cofactor screen holds exactly the points that drive zisklib's
    /// subgroup ladder into the identity, and the screened calls keep the
    /// reference verdict. These pins fail with the pure zisklib path: it
    /// aborts on them.
    #[test]
    fn bls_g1_cofactor_order_points_match_reference() {
        for point in bls_g1_cofactor_order_points() {
            assert!(bls12_381_g1_order_divides_cofactor(&point));

            for s in [scalar(1), scalar(2), scalar(3), [0xff; 32]] {
                let (ours, reference) = bls_g1_msm_both(&[(point, s)]);
                assert_eq!(ours, Err(()), "scalar {s:02x?}");
                assert_eq!(ours, reference);
            }

            let (ours, reference) = bls_pairing_both(&[(point, bls_g2(1))]);
            assert_eq!(ours, Err(()));
            assert_eq!(ours, reference);
        }

        // Everything else keeps the accelerated path: the identity, points
        // that fail the field or curve rule, subgroup points, and points off
        // the subgroup whose order carries r.
        assert!(!bls12_381_g1_order_divides_cofactor(&[0u8; 96]));
        let mut non_canonical = bls_g1(3);
        non_canonical[..48].copy_from_slice(&BLS12_381_FP_BE);
        assert!(!bls12_381_g1_order_divides_cofactor(&non_canonical));
        let mut off_curve = bls_g1(3);
        off_curve[95] ^= 1;
        assert!(!bls12_381_g1_order_divides_cofactor(&off_curve));
        assert!(!bls12_381_g1_order_divides_cofactor(&bls_g1(3)));

        let off_subgroup = bls_g1_large_order_off_subgroup();
        assert!(!bls12_381_g1_order_divides_cofactor(&off_subgroup));
        let (ours, reference) = bls_g1_msm_both(&[(off_subgroup, scalar(1))]);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bls_g2_msm_matches_reference() {
        let p = bls_g2(3);
        let q = bls_g2(5);

        for pairs in [
            vec![(p, scalar(1))],
            vec![(p, scalar(2))],
            vec![(p, scalar(0))],
            vec![(p, BLS12_381_FR_BE)],
            vec![(p, scalar(7)), (q, scalar(11))],
            vec![([0u8; 192], scalar(9)), (q, scalar(4))],
        ] {
            let (ours, reference) = bls_g2_msm_both(&pairs);
            assert!(ours.is_ok());
            assert_eq!(ours, reference);
        }

        let mut off_curve = p;
        off_curve[191] ^= 1;
        let (ours, reference) = bls_g2_msm_both(&[(off_curve, scalar(3))]);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bls_pairing_check_matches_reference() {
        let p = bls_g1(1);
        let q = bls_g2(1);
        let zero_g1 = [0u8; 96];
        let zero_g2 = [0u8; 192];

        // e(P, Q) != 1 for a single non-degenerate pair.
        let (ours, reference) = bls_pairing_both(&[(p, q)]);
        assert_eq!(ours, Ok(false));
        assert_eq!(ours, reference);

        // e(P, Q) · e(-P, Q) == 1.
        let (ours, reference) = bls_pairing_both(&[(p, q), (bls_g1_neg(&p), q)]);
        assert_eq!(ours, Ok(true));
        assert_eq!(ours, reference);

        // Pairs holding an infinity point contribute one.
        for pair in [(zero_g1, q), (p, zero_g2), (zero_g1, zero_g2)] {
            let (ours, reference) = bls_pairing_both(&[pair]);
            assert_eq!(ours, Ok(true));
            assert_eq!(ours, reference);
        }

        // Off-curve and non-canonical inputs halt, including next to an
        // infinity partner.
        let mut off_curve_g1 = p;
        off_curve_g1[95] ^= 1;
        let (ours, reference) = bls_pairing_both(&[(off_curve_g1, q)]);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        let mut non_canonical_g1 = p;
        non_canonical_g1[..48].copy_from_slice(&BLS12_381_FP_BE);
        let (ours, reference) = bls_pairing_both(&[(non_canonical_g1, zero_g2)]);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);

        let mut off_curve_g2 = q;
        off_curve_g2[191] ^= 1;
        let (ours, reference) = bls_pairing_both(&[(zero_g1, off_curve_g2)]);
        assert_eq!(ours, Err(()));
        assert_eq!(ours, reference);
    }

    #[test]
    fn bls_map_to_curve_matches_reference() {
        for seed in [0u8, 1, 2, 0xff] {
            let mut fp = [0u8; 48];
            fp[47] = seed;
            fp[0] = seed % 0x1a; // exercise the high limbs, staying under p

            let mut out = [0u8; 96];
            let ours = match bls12_381_fp_to_g1(&fp, &mut out) {
                0 => Ok(out),
                _ => Err(()),
            };
            let reference = DefaultCrypto.bls12_381_fp_to_g1(&fp).map_err(|_| ());
            assert!(ours.is_ok(), "fp_to_g1 seed {seed}");
            assert_eq!(ours, reference, "fp_to_g1 seed {seed}");

            let mut fp2 = [0u8; 96];
            fp2[..48].copy_from_slice(&fp);
            fp2[95] = seed.wrapping_add(1);
            let mut out = [0u8; 192];
            let ours = match bls12_381_fp2_to_g2(&fp2, &mut out) {
                0 => Ok(out),
                _ => Err(()),
            };
            let reference = DefaultCrypto
                .bls12_381_fp2_to_g2((fp2[..48].try_into().unwrap(), fp2[48..].try_into().unwrap()))
                .map_err(|_| ());
            assert!(ours.is_ok(), "fp2_to_g2 seed {seed}");
            assert_eq!(ours, reference, "fp2_to_g2 seed {seed}");
        }

        // A field element equal to p is not canonical; both sides halt.
        let mut out = [0u8; 96];
        assert_ne!(bls12_381_fp_to_g1(&BLS12_381_FP_BE, &mut out), 0);
        assert!(DefaultCrypto.bls12_381_fp_to_g1(&BLS12_381_FP_BE).is_err());

        let mut fp2 = [0u8; 96];
        fp2[48..].copy_from_slice(&BLS12_381_FP_BE);
        let mut out = [0u8; 192];
        assert_ne!(bls12_381_fp2_to_g2(&fp2, &mut out), 0);
        assert!(DefaultCrypto
            .bls12_381_fp2_to_g2(([0u8; 48], BLS12_381_FP_BE))
            .is_err());
    }

    /// An EIP-2537 fixture element of the isogeny kernel: the isogeny that
    /// closes the map to G1 sends it to the identity.
    const BLS_ISOGENY_KERNEL_FP: [u8; 48] = hex!(
        "0b3f3f9519ff3ab349e4ffc214f99998a697b02358fcfe44830e29129f58d6f9"
        "154a23fd14dfa660a75d4aaec9b607c3"
    );
    /// The EIP-2537 fixture element that the map sends to infinity.
    const BLS_FP_MAP_TO_INFINITY: [u8; 48] = hex!(
        "053287da0e0815dc9541794c8b35ddc31ba75821e2bf11e238e9978812a76828"
        "8b979af4a204a95c1e79dfedd252a3c5"
    );

    /// The two fixture classes whose cofactor clearing meets the identity.
    /// The map is valid on both: it returns the point at infinity. These
    /// pins abort with the pure zisklib path.
    #[test]
    fn bls_map_to_curve_identity_image_values_match_reference() {
        for fp in [BLS_ISOGENY_KERNEL_FP, BLS_FP_MAP_TO_INFINITY] {
            let mut out = [0u8; 96];
            assert_eq!(bls12_381_fp_to_g1(&fp, &mut out), 0, "fp {fp:02x?}");
            assert_eq!(out, DefaultCrypto.bls12_381_fp_to_g1(&fp).unwrap());
            assert_eq!(out, [0u8; 96], "fp {fp:02x?}");
        }
    }

    /// The variable that turns a re-run of this test binary into the child
    /// half of a tripwire. Its value is the test path the child runs.
    const TRIPWIRE_CHILD: &str = "ZISK_GUEST_TRIPWIRE_CHILD";
    /// The line the child prints before it makes the defective call.
    const TRIPWIRE_REACHED: &str = "tripwire child reached the defective call";

    /// True when this process is the child half of `test`. The child then
    /// makes the defective call itself.
    fn tripwire_child_of(test: &str) -> bool {
        if std::env::var(TRIPWIRE_CHILD).as_deref() != Ok(test) {
            return false;
        }
        println!("{TRIPWIRE_REACHED}");
        true
    }

    /// True when `test` dies on SIGABRT in a child process.
    ///
    /// The defective zisklib calls divide by zero inside an `extern "C"`
    /// shim, which is not allowed to unwind: the panic aborts the process,
    /// where neither `#[should_panic]` nor `catch_unwind` can see it. The
    /// child half is this same binary, re-run with the marker variable set.
    fn tripwire_aborts(test: &str) -> bool {
        use std::os::unix::process::ExitStatusExt;
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(TRIPWIRE_CHILD, test)
            .output()
            .expect("re-run of the test binary");
        assert!(
            String::from_utf8_lossy(&child.stdout).contains(TRIPWIRE_REACHED),
            "the child ran no body for {test}: the test path recorded in the \
             tripwire has drifted from the test name"
        );
        child.status.signal() == Some(6)
    }

    /// Tripwire pinning the UPSTREAM defect that motivates the cofactor
    /// screen: zisklib's `is_on_subgroup_bls12_381` drives its ladder
    /// through the identity for a point whose order divides the cofactor,
    /// and the raw curve syscall divides by zero there. If a ziskos bump
    /// makes this test FAIL, the upstream defect is fixed and the screen
    /// (and this tripwire) can be dropped.
    #[test]
    fn bls_g1_subgroup_cofactor_order_zisklib_defect_tripwire() {
        const TEST: &str = "hooks::tests::bls_g1_subgroup_cofactor_order_zisklib_defect_tripwire";
        if tripwire_child_of(TEST) {
            let [three_torsion, _, _] = bls_g1_cofactor_order_points();
            let point = zisklib::g1_bytes_be_to_u64_le_bls12_381(&three_torsion);
            let _ = zisklib::is_on_subgroup_bls12_381(&point);
            return;
        }
        assert!(
            tripwire_aborts(TEST),
            "zisklib's G1 subgroup check survives the 3-torsion point (0, 2) \
             — drop the cofactor screen in bls12_381_g1_msm, \
             bls12_381_pairing_check and verify_kzg_proof, and this tripwire"
        );
    }

    /// Tripwire pinning the UPSTREAM defect that motivates the software
    /// route of the two map hooks: zisklib's `map_to_curve_g1_bls12_381`
    /// clears the cofactor with the raw curve syscalls, which divide by zero
    /// on the identity the isogeny returns for a kernel element. If a ziskos
    /// bump makes this test FAIL, the upstream defect is fixed and both map
    /// hooks can take the accelerated path again.
    #[test]
    fn bls_map_to_curve_kernel_zisklib_defect_tripwire() {
        const TEST: &str = "hooks::tests::bls_map_to_curve_kernel_zisklib_defect_tripwire";
        if tripwire_child_of(TEST) {
            let u = zisklib::bytes_be_to_u64_le_fp_bls12_381(&BLS_ISOGENY_KERNEL_FP);
            let _ = zisklib::map_to_curve_g1_bls12_381(&u);
            return;
        }
        assert!(
            tripwire_aborts(TEST),
            "zisklib's G1 map to curve survives an isogeny-kernel element — \
             restore the accelerated path in bls12_381_fp_to_g1 and \
             bls12_381_fp2_to_g2, and drop this tripwire"
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
