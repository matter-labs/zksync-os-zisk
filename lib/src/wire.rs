//! Wire (de)serialization for the server-to-guest boundary.
//!
//! Encode the shared types with bincode 2.x through its serde path
//! (`bincode::serde::{encode_to_vec, decode_from_slice}`). Use the standard
//! configuration: little-endian bytes and variable-length integers. Keep the
//! types serde-derived.
//!
//! This module is the single source of truth for the wire format. The server
//! (input builder), the guest ELF, and the prover service must all use the
//! same configuration. A change here changes the wire format and needs a guest
//! rebuild and a verification-key rotation.
//!
//! bincode 2.x replaces the bincode 1.x fixint encoding used before. The
//! streaming decoder in `executor::stream` drives the same standard
//! configuration through bincode 2's `OwnedSerdeDecoder`, so the collecting
//! path and the streaming path stay byte-identical.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// The bincode 2.x configuration for the wire format: standard (little-endian,
/// variable-length integers). Every encode and decode on the boundary uses it.
pub fn config() -> bincode::config::Configuration {
    bincode::config::standard()
}

/// Encode a value to wire bytes. The shared types are plain data, so encoding
/// never fails; a failure is a programming error and panics.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, config()).expect("bincode encode must not fail")
}

/// Decode a value from wire bytes. Trailing bytes are allowed: the ZiSK guest
/// input is zero-padded to an 8-byte boundary, and the decoder reports how many
/// bytes it read and ignores the rest.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, bincode::error::DecodeError> {
    bincode::serde::decode_from_slice(bytes, config()).map(|(value, _read)| value)
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
        let bytes = encode(&value);
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
        let mut bytes = encode(&value);
        // Zero-pad to an 8-byte boundary, mirroring the ZiSK stdin framing.
        let pad = (8 - (bytes.len() % 8)) % 8;
        bytes.extend(std::iter::repeat_n(0u8, pad));
        let back: Sample = decode(&bytes).unwrap();
        assert_eq!(value, back);
    }
}
