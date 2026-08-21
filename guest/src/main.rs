//! ZiSK guest: proves ZKsync OS block execution using REVM.
//!
//! Every storage read is verified against a merkle proof.
//! The committed output is the BatchPublicInput hash matching the L1 format.
//! There is no unverified path — the guest always runs proven execution.

// Under `cargo test` the harness supplies the binary entrypoint; the ziskos
// entrypoint below is compiled out so the hook logic in `hooks` can be
// unit-tested on the host.
#![cfg_attr(not(test), no_main)]

mod hooks;

#[cfg(not(test))]
ziskos::entrypoint!(main);

#[cfg(not(test))]
fn main() {
    use zksync_os_zisk_lib::{crypto::CustomEvmCrypto, executor};

    // Install ZiSK-native crypto (keccak, secp256k1, bn254, etc.)
    // before any REVM execution. On the ZiSK target this uses hardware-
    // accelerated circuits; on native it falls back to software.
    revm::install_crypto(CustomEvmCrypto::default());

    // `install_crypto` only covers REVM *precompiles*. Transaction-envelope
    // signature recovery (`TxEnvelope::recover_signer`) dispatches through
    // alloy-consensus's OWN crypto backend, which otherwise falls back to
    // software k256 (the dominant proving cost on tx-heavy batches). Install
    // `CustomEvmCrypto` there too so tx recovery uses the accelerated
    // secp256k1 path (`secp256k1_ecdsa_address_recover_c` below).
    zksync_os_zisk_lib::crypto::install_tx_recovery_provider();

    // The wire format is bincode 2.x through its serde path, standard config
    // (little-endian, variable-length integers). Read the raw framed slice
    // (zero-copy on the zkVM target) and parse it with the lib's wire config
    // (`zksync_os_zisk_lib::wire`).
    //
    // Streaming read path: instead of decoding the whole `BatchInput`
    // (which materialises EVERY merkle sibling on the 507.75 MiB heap before
    // verification — the read-spam OOM floor), stream the storage proofs: each
    // is verified against the pre-state root and dropped before the next is
    // read, so the siblings are never all resident. The wire format is the same
    // for both paths and the commitment is byte-identical. See
    // `executor::stream`.
    let bytes = ziskos::io::read_input_slice();
    let (_output, commitment) = executor::execute_and_commit_streaming(bytes)
        .expect("failed to deserialize/execute BatchInput (streaming, bincode 2.x)");
    let hash_bytes: [u8; 32] = commitment.into();

    // `commit_slice` writes the byte stream directly (no u32-LE re-chunking),
    // so the committed public values are the keccak output verbatim.
    ziskos::io::commit_slice(&hash_bytes);
}

// `zksync-os-zisk-lib::crypto::CustomEvmCrypto` calls these C-ABI symbols on
// the ZiSK target; they must exist for the ELF to link. Every precompile an
// active fork exposes is wired to a real `ziskos::zisklib` backend below;
// the target-independent bodies live in `hooks`, where host-side unit tests
// compare them bit-for-bit against REVM's `DefaultCrypto` reference.
// A symbol that no REVM precompile dispatches to stays a self-identifying
// panic-stub: a batch that reaches one fails loudly under `ziskemu`, at
// which point the stub gets a real implementation.
// keccak256 is not stubbed — it routes through the tiny-keccak patch to the
// native-keccak syscall.
macro_rules! precompile_stub {
    ($name:ident ( $($arg:ident : $ty:ty),* ) $(-> $ret:ty)?) => {
        #[no_mangle]
        pub extern "C" fn $name( $($arg : $ty),* ) $(-> $ret)? {
            $( let _ = $arg; )*
            panic!(concat!(
                "ZiSK crypto precompile `", stringify!($name),
                "` is not implemented for v1.0.0-alpha (batch was not expected to \
                 invoke it); wire it to ziskos::zisklib to support batches that do."
            ));
        }
    };
}

// `secp256k1_ecdsa_verify_and_address_recover_c` covers a verify-and-recover
// entry point that no REVM precompile reaches: ecrecover routes through
// `secp256k1_ecdsa_address_recover_c` below.
precompile_stub!(secp256k1_ecdsa_verify_and_address_recover_c(sig: *const u8, msg: *const u8, pk: *const u8, output: *mut u8) -> u8);

// ======================== wired crypto hooks ========================
//
// Thin unsafe pointer shims over the safe bodies in `hooks`. Pointer widths
// are fixed by the callers in `lib/src/crypto/impls.rs`, which always pass
// buffers of exactly the sizes assumed here (REVM right-pads precompile
// inputs before dispatching).

/// SHA-256 digest for the `sha256` EVM precompile (0x02).
///
/// `input` points to `input_len` bytes; `output` receives the 32-byte
/// FIPS 180-4 digest. Backed by the ZiSK `sha256f` compression circuit via
/// `zisklib::sha256`.
#[no_mangle]
pub extern "C" fn sha256_c(input: *const u8, input_len: usize, output: *mut u8) {
    let input = unsafe { core::slice::from_raw_parts(input, input_len) };
    let digest = hooks::sha256(input);
    let out = unsafe { core::slice::from_raw_parts_mut(output, 32) };
    out.copy_from_slice(&digest);
}

/// BN254 G1 addition for the `ecAdd` EVM precompile (0x06, EIP-196).
///
/// `p1`/`p2` point to 64-byte big-endian affine points (x ‖ y, all zeros =
/// infinity); on success `ret` receives the 64-byte sum. Returns 0 = success,
/// 1 = success with infinity result (`ret` zeroed), 2 = coordinate not in
/// field, 3 = point not on curve — the codes `impls.rs` maps to
/// `PrecompileHalt`. Backed by the `bn254_curve_add`/`dbl` syscalls via
/// `zisklib::add_complete_bn254`.
#[no_mangle]
pub extern "C" fn bn254_g1_add_c(p1: *const u8, p2: *const u8, ret: *mut u8) -> u8 {
    let p1 = unsafe { &*(p1 as *const [u8; 64]) };
    let p2 = unsafe { &*(p2 as *const [u8; 64]) };
    let out = unsafe { &mut *(ret as *mut [u8; 64]) };
    hooks::bn254_g1_add(p1, p2, out)
}

/// BN254 G1 scalar multiplication for the `ecMul` EVM precompile (0x07,
/// EIP-196).
///
/// `point` is a 64-byte big-endian affine point, `scalar` a 32-byte
/// big-endian integer (arbitrary, reduced mod the group order inside).
/// Output format and return codes are identical to `bn254_g1_add_c`.
/// Backed by the accelerated double-and-add in `zisklib::mul_complete_bn254`.
#[no_mangle]
pub extern "C" fn bn254_g1_mul_c(point: *const u8, scalar: *const u8, ret: *mut u8) -> u8 {
    let point = unsafe { &*(point as *const [u8; 64]) };
    let scalar = unsafe { &*(scalar as *const [u8; 32]) };
    let out = unsafe { &mut *(ret as *mut [u8; 64]) };
    hooks::bn254_g1_mul(point, scalar, out)
}

/// BN254 pairing check for the `ecPairing` EVM precompile (0x08, EIP-197).
///
/// `pairs` points to `num_pairs` × 192-byte elements (G1 ‖ G2 in EVM byte
/// order: G2 = x_im ‖ x_re ‖ y_im ‖ y_re). Returns 0 = product of pairings
/// is one, 1 = it is not, 2..=6 = validation error (see `impls.rs`).
/// Backed by the bn254 Miller-loop/final-exponentiation circuits via
/// `zisklib::pairing_check_bn254`, plus an upfront coordinate-canonicality
/// check in `hooks` that zisklib skips for infinity-paired points.
#[no_mangle]
pub extern "C" fn bn254_pairing_check_c(pairs: *const u8, num_pairs: usize) -> u8 {
    let pairs = unsafe { core::slice::from_raw_parts(pairs, num_pairs * 192) };
    hooks::bn254_pairing_check(pairs)
}

/// EIP-198 modular exponentiation for the `modExp` EVM precompile (0x05).
///
/// Operands are arbitrary-length big-endian byte strings (zero-length
/// allowed). Writes `base^exp mod modulus`, big-endian and left-zero-padded
/// to `modulus_len`, into `ret_ptr` (which the caller sizes to
/// `modulus_len`) and returns the written length (always `modulus_len`).
/// Backed by the `arith256` syscalls + `bin_decomp` fcall via
/// `zisklib::modexp`, which handles arbitrary-size operands (multi-limb
/// long-division path for moduli beyond 256 bits).
#[no_mangle]
pub extern "C" fn modexp_bytes_c(
    base_ptr: *const u8,
    base_len: usize,
    exp_ptr: *const u8,
    exp_len: usize,
    modulus_ptr: *const u8,
    modulus_len: usize,
    ret_ptr: *mut u8,
) -> usize {
    let base = unsafe { core::slice::from_raw_parts(base_ptr, base_len) };
    let exp = unsafe { core::slice::from_raw_parts(exp_ptr, exp_len) };
    let modulus = unsafe { core::slice::from_raw_parts(modulus_ptr, modulus_len) };
    let out = unsafe { core::slice::from_raw_parts_mut(ret_ptr, modulus_len) };
    hooks::modexp(base, exp, modulus, out)
}

/// secp256r1 (P-256) ECDSA verification for the `P256VERIFY` precompile
/// (RIP-7212 / EIP-7951).
///
/// `msg` points to the 32-byte message hash, `sig` to r ‖ s (64 bytes,
/// big-endian), `pk` to the uncompressed public key x ‖ y (64 bytes,
/// big-endian). Returns the exact RIP-7212 predicate: r, s ∈ [1, n-1], pk a
/// canonical non-identity curve point, high-s accepted. Backed by the
/// `secp256r1_add`/`dbl` syscalls + ecdsa-verify fcall hint via
/// `zisklib::ecdsa_verify_secp256r1`.
#[no_mangle]
pub extern "C" fn secp256r1_ecdsa_verify_c(msg: *const u8, sig: *const u8, pk: *const u8) -> bool {
    let msg = unsafe { &*(msg as *const [u8; 32]) };
    let sig = unsafe { &*(sig as *const [u8; 64]) };
    let pk = unsafe { &*(pk as *const [u8; 64]) };
    hooks::secp256r1_verify(msg, sig, pk)
}

/// Recover the signer's Ethereum-address hash from an ECDSA signature.
///
/// Called on the ZiSK target from both the REVM `secp256k1_ecrecover`
/// precompile and alloy-consensus's transaction signer recovery — every L2
/// tx signature goes through here, so unlike the stubs above this is a real
/// implementation backed by ziskos's accelerated secp256k1 circuits.
///
/// `sig` points to 64 bytes (r ‖ s, big-endian), `recid` is the y-parity
/// (0 or 1), `msg` points to the 32-byte prehash. On success `output[0..32]`
/// receives `keccak256(pubkey_x ‖ pubkey_y)` with the top 12 bytes zeroed, so
/// `output[12..32]` is the 20-byte address — matching REVM's k256 reference
/// (`hash[..12].fill(0)`) and impls.rs's `Address::from_slice(&output[12..])`.
/// Returns 0 on success, 1 on failure.
///
/// The public key is recovered via ziskos v0.18.0's `zkvm_secp256k1_ecrecover`
/// (a `#[no_mangle]` C symbol from `ziskos::zisklib::zkvm_accelerators` on the
/// zisk target). On-target it uses the accelerated secp256k1 add/dbl ops
/// (0xf4/0xf5) + arith_eq circuits — NOT software k256. The signature `s` is
/// not normalized here: alloy's `recover_signer` enforces EIP-2 low-`s` before
/// dispatching, and negating `s` while flipping `recid` yields the same point,
/// so the recovered key (and thus the address) is identical to the k256 path.
#[no_mangle]
pub extern "C" fn secp256k1_ecdsa_address_recover_c(
    sig: *const u8,
    recid: u8,
    msg: *const u8,
    output: *mut u8,
) -> u8 {
    // ziskos accelerated ecrecover. C ABI (zkvm_accelerators.h):
    //   zkvm_status zkvm_secp256k1_ecrecover(const zkvm_secp256k1_hash* msg,
    //       const zkvm_secp256k1_signature* sig, uint8_t recid,
    //       zkvm_secp256k1_pubkey* output);
    // hash = bytes32, signature = pubkey = bytes64 (all thin ptrs);
    // zkvm_status is a C enum { ZKVM_EOK = 0, ZKVM_EFAIL = -1 } => c_int/i32.
    extern "C" {
        fn zkvm_secp256k1_ecrecover(
            msg: *const u8,
            sig: *const u8,
            recid: u8,
            output: *mut u8,
        ) -> i32;
    }

    // Recover the 64-byte uncompressed public key (x ‖ y, big-endian).
    let mut pubkey = [0u8; 64];
    let status = unsafe { zkvm_secp256k1_ecrecover(msg, sig, recid, pubkey.as_mut_ptr()) };
    if status != 0 {
        return 1;
    }

    // address = keccak256(pubkey)[12..]; zero the top 12 bytes to match the
    // reference precompile output. Uses the ZiSK-accelerated keccak.
    let hash = zksync_os_zisk_lib::hash::keccak256(&pubkey);
    let out = unsafe { core::slice::from_raw_parts_mut(output, 32) };
    out[..12].fill(0);
    out[12..].copy_from_slice(&hash.as_slice()[12..]);
    0
}

/// BLAKE2b compression function F for the `blake2f` EVM precompile (0x09,
/// EIP-152).
///
/// `h` points to the 8-word state (updated in place), `m` to the 16-word
/// message block, `t` to the 2-word offset counter; `f` is the finalization
/// flag (0 or 1). Backed by the ZiSK `blake2b_round` syscall via
/// `zisklib::blake2b_compress`.
#[no_mangle]
pub extern "C" fn blake2b_compress_c(
    rounds: u32,
    h: *mut u64,
    m: *const u64,
    t: *const u64,
    f: u8,
) {
    let h = unsafe { &mut *(h as *mut [u64; 8]) };
    let m = unsafe { &*(m as *const [u64; 16]) };
    let t = unsafe { &*(t as *const [u64; 2]) };
    hooks::blake2b_compress(rounds, h, m, t, f != 0);
}

/// KZG point evaluation for the `pointEvaluation` precompile (0x0a,
/// EIP-4844).
///
/// `z`/`y` point to 32-byte big-endian scalars, `commitment`/`proof` to
/// 48-byte compressed G1 points. Returns true iff the proof holds. Backed by
/// the bls12-381 pairing circuits via `zisklib::verify_kzg_proof`.
#[no_mangle]
pub extern "C" fn verify_kzg_proof_c(
    z: *const u8,
    y: *const u8,
    commitment: *const u8,
    proof: *const u8,
) -> bool {
    let z = unsafe { &*(z as *const [u8; 32]) };
    let y = unsafe { &*(y as *const [u8; 32]) };
    let commitment = unsafe { &*(commitment as *const [u8; 48]) };
    let proof = unsafe { &*(proof as *const [u8; 48]) };
    hooks::verify_kzg_proof(z, y, commitment, proof)
}

/// BLS12-381 G1 addition for the `BLS12_G1ADD` precompile (0x0b, EIP-2537).
///
/// `a`/`b` point to 96-byte big-endian affine points (x ‖ y, all zeros =
/// infinity); `ret` receives the 96-byte sum. Returns 0 = success,
/// 1 = success with infinity result (`ret` zeroed), 2 and above = validation
/// error — the codes `impls.rs` maps to `PrecompileHalt`.
#[no_mangle]
pub extern "C" fn bls12_381_g1_add_c(ret: *mut u8, a: *const u8, b: *const u8) -> u8 {
    let a = unsafe { &*(a as *const [u8; 96]) };
    let b = unsafe { &*(b as *const [u8; 96]) };
    let out = unsafe { &mut *(ret as *mut [u8; 96]) };
    hooks::bls12_381_g1_add(a, b, out)
}

/// BLS12-381 G1 multi-scalar multiplication for the `BLS12_G1MSM` precompile
/// (0x0c, EIP-2537).
///
/// `pairs` points to `num_pairs` × 128-byte elements (96-byte G1 point ‖
/// 32-byte big-endian scalar); `ret` receives the 96-byte sum. Return codes
/// match `bls12_381_g1_add_c`.
#[no_mangle]
pub extern "C" fn bls12_381_g1_msm_c(ret: *mut u8, pairs: *const u8, num_pairs: usize) -> u8 {
    let pairs = unsafe { core::slice::from_raw_parts(pairs, num_pairs * 128) };
    let out = unsafe { &mut *(ret as *mut [u8; 96]) };
    hooks::bls12_381_g1_msm(pairs, out)
}

/// BLS12-381 G2 addition for the `BLS12_G2ADD` precompile (0x0d, EIP-2537).
///
/// `a`/`b` point to 192-byte big-endian affine points (x_c0 ‖ x_c1 ‖ y_c0 ‖
/// y_c1, all zeros = infinity); `ret` receives the 192-byte sum. Return codes
/// match `bls12_381_g1_add_c`.
#[no_mangle]
pub extern "C" fn bls12_381_g2_add_c(ret: *mut u8, a: *const u8, b: *const u8) -> u8 {
    let a = unsafe { &*(a as *const [u8; 192]) };
    let b = unsafe { &*(b as *const [u8; 192]) };
    let out = unsafe { &mut *(ret as *mut [u8; 192]) };
    hooks::bls12_381_g2_add(a, b, out)
}

/// BLS12-381 G2 multi-scalar multiplication for the `BLS12_G2MSM` precompile
/// (0x0e, EIP-2537).
///
/// `pairs` points to `num_pairs` × 224-byte elements (192-byte G2 point ‖
/// 32-byte big-endian scalar); `ret` receives the 192-byte sum. Return codes
/// match `bls12_381_g1_add_c`.
#[no_mangle]
pub extern "C" fn bls12_381_g2_msm_c(ret: *mut u8, pairs: *const u8, num_pairs: usize) -> u8 {
    let pairs = unsafe { core::slice::from_raw_parts(pairs, num_pairs * 224) };
    let out = unsafe { &mut *(ret as *mut [u8; 192]) };
    hooks::bls12_381_g2_msm(pairs, out)
}

/// BLS12-381 pairing check for the `BLS12_PAIRING_CHECK` precompile (0x0f,
/// EIP-2537).
///
/// `pairs` points to `num_pairs` × 288-byte elements (96-byte G1 ‖ 192-byte
/// G2). Returns 0 = product of pairings is one, 1 = it is not, 2 and above =
/// validation error (see `impls.rs`).
#[no_mangle]
pub extern "C" fn bls12_381_pairing_check_c(pairs: *const u8, num_pairs: usize) -> u8 {
    let pairs = unsafe { core::slice::from_raw_parts(pairs, num_pairs * 288) };
    hooks::bls12_381_pairing_check(pairs)
}

/// BLS12-381 map-to-curve for the `BLS12_MAP_FP_TO_G1` precompile (0x10,
/// EIP-2537).
///
/// `fp` points to a 48-byte big-endian field element; `ret` receives the
/// 96-byte G1 point. Returns 0 = success, 1 = the input is not in the field.
#[no_mangle]
pub extern "C" fn bls12_381_fp_to_g1_c(ret: *mut u8, fp: *const u8) -> u8 {
    let fp = unsafe { &*(fp as *const [u8; 48]) };
    let out = unsafe { &mut *(ret as *mut [u8; 96]) };
    hooks::bls12_381_fp_to_g1(fp, out)
}

/// BLS12-381 map-to-curve for the `BLS12_MAP_FP2_TO_G2` precompile (0x11,
/// EIP-2537).
///
/// `fp2` points to a 96-byte Fp2 element (c0 ‖ c1, big-endian); `ret`
/// receives the 192-byte G2 point. Returns 0 = success, 1 = an input
/// component is not in the field.
#[no_mangle]
pub extern "C" fn bls12_381_fp2_to_g2_c(ret: *mut u8, fp2: *const u8) -> u8 {
    let fp2 = unsafe { &*(fp2 as *const [u8; 96]) };
    let out = unsafe { &mut *(ret as *mut [u8; 192]) };
    hooks::bls12_381_fp2_to_g2(fp2, out)
}
