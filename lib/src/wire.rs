//! Wire (de)serialization for the server-to-guest boundary.
//!
//! Encode the shared types with bincode 2.x through its serde path
//! (`bincode::serde::{encode_to_vec, decode_from_slice}`). Use the standard
//! configuration: little-endian bytes and variable-length integers. Keep the
//! types serde-derived.
//!
//! This module is the single source of truth for the wire format. Writers emit
//! the current format from [`crate::types`]; readers dispatch on the leading
//! version and normalize supported historical formats into the current
//! in-memory representation. A change here still needs a guest rebuild and a
//! verification-key rotation, but does not invalidate already-released input
//! bytes while their decoder remains supported.
//!
//! bincode 2.x replaces the bincode 1.x fixint encoding used before. The
//! streaming decoder in `executor::stream` drives the same standard
//! configuration through bincode 2's `OwnedSerdeDecoder`, so the collecting
//! path and the streaming path stay byte-identical.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::types::{BatchInput, BATCH_INPUT_VERSION};

/// Frozen definitions for the released wire-v3 schema.
pub mod v3;
/// Frozen definitions for the released wire-v5 schema.
pub mod v5;

/// Wire versions this revision can execute. Wire v4 was never released from
/// `main`, so accepting it would bless an internal development format without
/// a compatibility obligation.
pub const SUPPORTED_BATCH_INPUT_VERSIONS: &[u32] = &[
    v3::BATCH_INPUT_VERSION,
    v5::BATCH_INPUT_VERSION,
    BATCH_INPUT_VERSION,
];

/// The bincode 2.x configuration for the wire format: standard (little-endian,
/// variable-length integers). Every encode and decode on the boundary uses it.
pub fn config() -> bincode::config::Configuration {
    bincode::config::standard()
}

/// Encode a value to wire bytes. The host assembles the guest input with this
/// function, so an encode failure reaches the caller as an error and degrades
/// that one batch.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(value, config())
}

/// Decode a value from wire bytes. Trailing bytes are allowed: the ZiSK guest
/// input is zero-padded to an 8-byte boundary, and the decoder reports how many
/// bytes it read and ignores the rest.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::error::DecodeError> {
    bincode::serde::decode_from_slice(bytes, config()).map(|(value, _read)| value)
}

/// Read the leading `BatchInput.version` without deserializing the witness.
///
/// Bincode's positional struct encoding starts with the first field, so this
/// remains an O(1) probe and lets callers choose the correct schema before a
/// later field can be misparsed.
pub fn batch_input_version(bytes: &[u8]) -> Result<u32, bincode::error::DecodeError> {
    decode(bytes)
}

/// Decode any supported `BatchInput` wire version and normalize it into the
/// current in-memory representation used by the executor.
pub fn decode_batch_input(bytes: &[u8]) -> Result<BatchInput, String> {
    let version =
        batch_input_version(bytes).map_err(|e| format!("read BatchInput version: {e}"))?;
    match version {
        v3::BATCH_INPUT_VERSION => decode::<v3::BatchInput>(bytes)
            .map(Into::into)
            .map_err(|e| format!("deserialize BatchInput wire v3: {e}")),
        v5::BATCH_INPUT_VERSION => decode::<v5::BatchInput>(bytes)
            .map(Into::into)
            .map_err(|e| format!("deserialize BatchInput wire v5: {e}")),
        BATCH_INPUT_VERSION => decode::<BatchInput>(bytes)
            .map_err(|e| format!("deserialize BatchInput wire v{BATCH_INPUT_VERSION}: {e}")),
        _ => Err(format!(
            "unsupported BatchInput wire-format version {version} (supported: {})",
            SUPPORTED_BATCH_INPUT_VERSIONS
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Sample {
        a: u32,
        b: Vec<u8>,
        c: Option<u64>,
    }

    #[test]
    fn encode_decode_roundtrip() {
        let value = Sample {
            a: 0xDEAD_BEEF,
            b: vec![1, 2, 3, 4, 5],
            c: Some(42),
        };
        let bytes = encode(&value).unwrap();
        let back: Sample = decode(&bytes).unwrap();
        assert_eq!(value, back);
    }

    #[test]
    fn decode_ignores_trailing_padding() {
        let value = Sample {
            a: 7,
            b: vec![9, 9],
            c: None,
        };
        let mut bytes = encode(&value).unwrap();
        // Zero-pad to an 8-byte boundary, mirroring the ZiSK stdin framing.
        let pad = (8 - (bytes.len() % 8)) % 8;
        bytes.extend(std::iter::repeat_n(0u8, pad));
        let back: Sample = decode(&bytes).unwrap();
        assert_eq!(value, back);
    }

    #[test]
    fn batch_input_decoder_rejects_unreleased_wire_v4_before_the_payload() {
        let bytes = encode(&4u32).unwrap();
        let error = match decode_batch_input(&bytes) {
            Ok(_) => panic!("wire v4 unexpectedly decoded"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            "unsupported BatchInput wire-format version 4 (supported: 3, 5, 6)"
        );
    }
}
