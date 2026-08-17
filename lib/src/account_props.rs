//! Deterministic derivation of native ZKsync OS `AccountProperties` fields
//! for EVM code.
//!
//! Mirrors `basic_system/.../flat_storage_model/account_cache.rs` +
//! `evm_interpreter` (draft-0.4.0): every code-derived field of an account's
//! 124-byte properties blob is a pure function of the deployed code, so the
//! guest can recompute and verify them instead of trusting the witness.
//!
//! Native recipe (EVM):
//! - artifacts = jumpdest bitmap: `ceil(code_len / 64)` u64 words,
//!   little-endian, bit `i` set iff `code[i]` is a JUMPDEST outside PUSH
//!   immediates (code version 1, `ARTIFACTS_CACHING_CODE_VERSION_BYTE`).
//!   Every native path that stores code (`deploy_code`, `set_bytecode_details`,
//!   `set_delegation`) writes that one code version, so the guest derives it
//!   and never reads it from the witness. Code version 0 belongs to the
//!   all-zero blob of an account that holds no code.
//! - padding: code zero-padded to 8-byte (`BYTECODE_ALIGNMENT`) alignment.
//! - `bytecode_hash = blake2s256(code || padding || artifacts)`; the preimage
//!   blob stored under it is exactly that concatenation.
//! - `observable_bytecode_hash = keccak256(code)`;
//!   `unpadded_code_len = observable_bytecode_len = code.len()`.
//! - versioning u64: deployment status byte 7 (1 = deployed, 2 = EIP-7702
//!   delegated), EE type byte 6 (EVM = 1), code version byte 5; aux bytes
//!   unused.
//! - EIP-7702 delegation: code = `0xef0100 || address` (23 bytes), no
//!   artifacts, same hashing; clearing a delegation zeroes every field.

use crate::merkle::AccountProperties;
use blake2::{Blake2s256, Digest};
use revm::primitives::{keccak256, B256};

pub const EVM_EE_BYTE: u8 = 1;
pub const DEPLOYED_STATUS_BYTE: u8 = 1;
pub const DELEGATED_STATUS_BYTE: u8 = 2;
pub const ARTIFACTS_CACHING_CODE_VERSION: u8 = 1;
pub const EIP7702_DELEGATION_MARKER: [u8; 3] = [0xef, 0x01, 0x00];

const BYTECODE_ALIGNMENT: usize = 8;

const JUMPDEST: u8 = 0x5b;
const PUSH1: u8 = 0x60;
const PUSH32: u8 = 0x7f;

/// The code-derived subset of `AccountProperties` (everything except nonce
/// and balance, which REVM verifies directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeFields {
    pub versioning: u64,
    pub bytecode_hash: B256,
    pub unpadded_code_len: u32,
    pub artifacts_len: u32,
    pub observable_bytecode_hash: B256,
    pub observable_bytecode_len: u32,
}

impl CodeFields {
    /// An account with no code (EOA or cleared delegation): every field zero.
    pub fn empty() -> Self {
        Self {
            versioning: 0,
            bytecode_hash: B256::ZERO,
            unpadded_code_len: 0,
            artifacts_len: 0,
            observable_bytecode_hash: B256::ZERO,
            observable_bytecode_len: 0,
        }
    }

    /// Extract the code-derived fields from a decoded witness blob.
    pub fn of(props: &AccountProperties) -> Self {
        Self {
            versioning: props.versioning,
            bytecode_hash: props.bytecode_hash,
            unpadded_code_len: props.unpadded_code_len,
            artifacts_len: props.artifacts_len,
            observable_bytecode_hash: props.observable_bytecode_hash,
            observable_bytecode_len: props.observable_bytecode_len,
        }
    }
}

/// EVM jumpdest bitmap exactly as `evm_interpreter::analyze` builds it:
/// bit `i` (byte `i / 8`, bit `i % 8`, little-endian u64 words) set iff
/// `code[i]` is JUMPDEST and not inside PUSH immediate data. Length is
/// `ceil(code_len / 64)` u64 words.
pub fn evm_jumpdest_bitmap(code: &[u8]) -> Vec<u8> {
    let words = code.len().div_ceil(64);
    let mut bitmap = vec![0u8; words * 8];
    let mut i = 0;
    while i < code.len() {
        let op = code[i];
        if op == JUMPDEST {
            bitmap[i / 8] |= 1 << (i % 8);
            i += 1;
        } else if (PUSH1..=PUSH32).contains(&op) {
            i += 1 + (op - PUSH1 + 1) as usize;
        } else {
            i += 1;
        }
    }
    bitmap
}

fn versioning(status: u8, code_version: u8) -> u64 {
    ((status as u64) << 56) | ((EVM_EE_BYTE as u64) << 48) | ((code_version as u64) << 40)
}

/// Derive every code-dependent `AccountProperties` field for EVM code.
///
/// The code version is derived, not read: native stores code only under
/// `ARTIFACTS_CACHING_CODE_VERSION`, so one account holding one code has one
/// legal leaf, and a blob that claims any other code version fails the field
/// comparison at the caller.
///
/// A 23-byte `0xef0100 || address` blob is an EIP-7702 delegation designator:
/// delegated status, no artifacts, code version 1 — matching native
/// `set_delegation`.
pub fn evm_code_fields(code: &[u8]) -> CodeFields {
    let is_delegation =
        code.len() == 23 && code[..3] == EIP7702_DELEGATION_MARKER;

    let artifacts = if is_delegation {
        Vec::new()
    } else {
        evm_jumpdest_bitmap(code)
    };

    let padding_len = (BYTECODE_ALIGNMENT - (code.len() % BYTECODE_ALIGNMENT)) % BYTECODE_ALIGNMENT;
    let mut hasher = Blake2s256::new();
    hasher.update(code);
    hasher.update(&[0u8; BYTECODE_ALIGNMENT - 1][..padding_len]);
    hasher.update(&artifacts);
    let bytecode_hash = B256::from_slice(&hasher.finalize());

    let status = if is_delegation {
        DELEGATED_STATUS_BYTE
    } else {
        DEPLOYED_STATUS_BYTE
    };

    CodeFields {
        versioning: versioning(status, ARTIFACTS_CACHING_CODE_VERSION),
        bytecode_hash,
        unpadded_code_len: code.len() as u32,
        artifacts_len: artifacts.len() as u32,
        observable_bytecode_hash: keccak256(code),
        observable_bytecode_len: code.len() as u32,
    }
}

/// Whether a no-observable-code account's fields are one of the two
/// canonical native encodings:
/// - never-deployed (or delegation-cleared) accounts keep every code field
///   zero;
/// - an account DEPLOYED with empty runtime code (native `deploy_code` runs
///   for every completed deployment regardless of code length) carries
///   deployed/EVM versioning with the hashes of the empty blob
///   (`bytecode_hash = blake2s("")`, `observable = keccak256("")`, lens 0).
///
/// The two encodings are two distinct leaves, so the predicate belongs to the
/// system force-deploy path alone — the trusted hole of an upgrade batch, where
/// REVM models no post-state and only the tree authentication and this
/// self-consistency check constrain the fields. An account execution wrote has
/// its code fields DERIVED, so it has one legal leaf.
pub fn no_code_fields_valid(props: &AccountProperties) -> bool {
    let actual = CodeFields::of(props);
    actual == CodeFields::empty() || actual == evm_code_fields(&[])
}

/// Whether the blob is the zeroed account leaf: nonce 0, balance 0, and every
/// code field zero. Native writes exactly this encoding for an account that
/// EIP-6780 destruction removes, and the 124-byte layout has no other fields,
/// so the predicate pins the whole blob.
pub fn is_zeroed_account(props: &AccountProperties) -> bool {
    props.nonce == 0
        && props.balance == [0u8; 32]
        && CodeFields::of(props) == CodeFields::empty()
}

/// The full preimage blob stored under `bytecode_hash`:
/// `code || zero padding to 8 || artifacts`.
pub fn evm_bytecode_preimage(code: &[u8]) -> Vec<u8> {
    let is_delegation =
        code.len() == 23 && code[..3] == EIP7702_DELEGATION_MARKER;
    let artifacts = if is_delegation {
        Vec::new()
    } else {
        evm_jumpdest_bitmap(code)
    };
    let padding_len = (BYTECODE_ALIGNMENT - (code.len() % BYTECODE_ALIGNMENT)) % BYTECODE_ALIGNMENT;
    let mut blob = Vec::with_capacity(code.len() + padding_len + artifacts.len());
    blob.extend_from_slice(code);
    blob.extend_from_slice(&[0u8; BYTECODE_ALIGNMENT - 1][..padding_len]);
    blob.extend_from_slice(&artifacts);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jumpdest_bitmap_skips_push_data() {
        // PUSH1 0x5b (immediate, not a jumpdest), JUMPDEST, STOP
        let code = [0x60, 0x5b, 0x5b, 0x00];
        let bitmap = evm_jumpdest_bitmap(&code);
        assert_eq!(bitmap.len(), 8); // one u64 word
        assert_eq!(bitmap[0], 0b0000_0100); // only offset 2 set
    }

    #[test]
    fn bitmap_length_is_u64_granular() {
        assert_eq!(evm_jumpdest_bitmap(&[0u8; 64]).len(), 8);
        assert_eq!(evm_jumpdest_bitmap(&[0u8; 65]).len(), 16);
        assert_eq!(evm_jumpdest_bitmap(&[]).len(), 0);
    }

    #[test]
    fn delegation_designator_fields() {
        let mut code = vec![0xef, 0x01, 0x00];
        code.extend_from_slice(&[0x11; 20]);
        let fields = evm_code_fields(&code);
        assert_eq!(fields.artifacts_len, 0);
        assert_eq!(fields.unpadded_code_len, 23);
        assert_eq!(fields.versioning >> 56, DELEGATED_STATUS_BYTE as u64);
        assert_eq!((fields.versioning >> 48) as u8, EVM_EE_BYTE);
        // Native `set_delegation` tags the designator with the artifact-caching
        // code version even though it caches no artifacts.
        assert_eq!((fields.versioning >> 40) as u8, ARTIFACTS_CACHING_CODE_VERSION);
        // blake2s over code + 1 byte of padding (23 -> 24), no artifacts
        let mut h = Blake2s256::new();
        h.update(&code);
        h.update([0u8]);
        assert_eq!(fields.bytecode_hash, B256::from_slice(&h.finalize()));
    }

    #[test]
    fn deployed_code_fields_roundtrip_with_preimage() {
        let code = [0x5b, 0x60, 0x01, 0x00, 0x5b]; // 5 bytes -> pad 3
        let fields = evm_code_fields(&code);
        let blob = evm_bytecode_preimage(&code);
        assert_eq!(blob.len(), 5 + 3 + 8);
        let mut h = Blake2s256::new();
        h.update(&blob);
        assert_eq!(fields.bytecode_hash, B256::from_slice(&h.finalize()));
        assert_eq!(fields.artifacts_len, 8);
        assert_eq!(fields.versioning, 0x0101_0100_0000_0000);
        assert_eq!(fields.observable_bytecode_hash, keccak256(code));
    }

    fn props_from(fields: &CodeFields, nonce: u64) -> AccountProperties {
        AccountProperties {
            versioning: fields.versioning,
            nonce,
            balance: [0u8; 32],
            bytecode_hash: fields.bytecode_hash,
            unpadded_code_len: fields.unpadded_code_len,
            artifacts_len: fields.artifacts_len,
            observable_bytecode_hash: fields.observable_bytecode_hash,
            observable_bytecode_len: fields.observable_bytecode_len,
        }
    }

    /// `observable_bytecode_len` separates the native shapes that hold code
    /// from the ones that do not. Post-execution verification reads the
    /// authenticated pre-state length to tell an account whose code the batch
    /// cleared from one whose code fields the batch left alone, so the two
    /// no-code shapes must both report zero and every shape that holds code
    /// must report the unpadded length of that code.
    #[test]
    fn observable_bytecode_len_marks_the_shapes_that_hold_code() {
        assert_eq!(CodeFields::empty().observable_bytecode_len, 0);
        assert_eq!(evm_code_fields(&[]).observable_bytecode_len, 0);

        let mut designator = EIP7702_DELEGATION_MARKER.to_vec();
        designator.extend_from_slice(&[0x22; 20]);
        assert_eq!(evm_code_fields(&designator).observable_bytecode_len, 23);
        assert_eq!(evm_code_fields(&[0x5b, 0x00]).observable_bytecode_len, 2);
    }

    /// Both canonical no-observable-code encodings must be accepted, and
    /// nothing else. The predicate guards the system force-deploy path, where
    /// REVM models no post-state to derive the fields from. Pins the exact
    /// native deployed-empty materialization observed on v0.3.x
    /// (`deploy_code` with empty runtime code), including
    /// its code version: `deploy_code` writes the artifact-caching version for
    /// empty runtime code as well, so the pre-artifact-caching encoding of the
    /// same account is not a native encoding.
    #[test]
    fn no_code_fields_accepts_exactly_the_two_native_encodings() {
        // Arm 1: never-deployed (or delegation-cleared) — all zero.
        assert!(no_code_fields_valid(&props_from(&CodeFields::empty(), 7)));

        // Arm 2: deployed with empty runtime code, code version 1.
        let deployed_empty = evm_code_fields(&[]);
        assert_eq!(deployed_empty.versioning, 0x0101_0100_0000_0000);
        assert_eq!(
            deployed_empty.bytecode_hash,
            B256::from_slice(&Blake2s256::digest([])), // blake2s("")
        );
        assert_eq!(deployed_empty.observable_bytecode_hash, keccak256([])); // keccak256("")
        assert_eq!(deployed_empty.unpadded_code_len, 0);
        assert_eq!(deployed_empty.artifacts_len, 0);
        assert_eq!(deployed_empty.observable_bytecode_len, 0);
        assert!(no_code_fields_valid(&props_from(&deployed_empty, 1)));

        // A claimed code version other than the native one is rejected, so a
        // deployed-empty account has ONE legal leaf. For empty runtime code the
        // pre-artifact-caching encoding differs from the native one in the
        // versioning word alone: both carry no artifacts and the same hashes.
        let mut pre_artifact_caching = deployed_empty.clone();
        pre_artifact_caching.versioning = 0x0101_0000_0000_0000; // code version 0
        assert!(!no_code_fields_valid(&props_from(&pre_artifact_caching, 1)));

        // Mixed encodings are rejected: deployed status with zero hashes...
        let mut mixed = CodeFields::empty();
        mixed.versioning = 0x0101_0100_0000_0000;
        assert!(!no_code_fields_valid(&props_from(&mixed, 1)));
        // ...zero status with the empty-blob hashes...
        let mut mixed = deployed_empty.clone();
        mixed.versioning = 0;
        assert!(!no_code_fields_valid(&props_from(&mixed, 1)));
        // ...a wrong bytecode_hash...
        let mut mixed = deployed_empty.clone();
        mixed.bytecode_hash = B256::repeat_byte(0x11);
        assert!(!no_code_fields_valid(&props_from(&mixed, 1)));
        // ...a nonzero claimed length...
        let mut mixed = deployed_empty.clone();
        mixed.unpadded_code_len = 1;
        assert!(!no_code_fields_valid(&props_from(&mixed, 1)));
        // ...or an unsupported code version.
        let mut mixed = deployed_empty;
        mixed.versioning = 0x0101_0200_0000_0000; // code version 2
        assert!(!no_code_fields_valid(&props_from(&mixed, 1)));
    }
}
