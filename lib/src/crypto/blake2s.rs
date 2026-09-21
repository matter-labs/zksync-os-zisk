//! BLAKE2s-256 built on the compression function F of RFC 7693, section 3.2.
//!
//! On the ZiSK target F is one `blake2sf` precompile call
//! (`ziskos::zisklib::blake2s_compress`, reached through the guest's
//! `blake2s_compress_c` hook, see `ffi.rs`); everywhere else it is the
//! software function in [`software`]. The hasher around F is the same on both
//! sides: the parameter block of an unkeyed 32-byte digest folded into the IV,
//! 64-byte blocks, the byte counter `t`, the last-block flag on the final
//! compression, and the `h ^= v_lo ^ v_hi` feed-forward that F performs.
//!
//! The production callers (`account_props`, `block_roots`) use this type on
//! the ZiSK target only; off-target they keep the `blake2` crate, which the
//! tests here compare against.

/// The BLAKE2s initialization vector: the first 32 bits of the fractional
/// parts of the square roots of the first eight primes.
pub const IV: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB,
    0x5BE0_CD19,
];

/// Word 0 of the parameter block for an unkeyed 32-byte digest: digest_length
/// = 32, key_length = 0, fanout = 1, depth = 1 (RFC 7693, section 2.5). The
/// remaining parameter words are zero, so only this word changes the IV.
const PARAM_BLOCK_WORD0: u32 = 0x0101_0020;

/// Message block size in bytes.
pub const BLOCK_BYTES: usize = 64;
/// Digest size in bytes.
pub const DIGEST_BYTES: usize = 32;

/// BLAKE2s-256 streaming hasher (unkeyed).
#[derive(Clone)]
pub struct Blake2s256 {
    h: [u32; 8],
    buf: [u8; BLOCK_BYTES],
    buf_len: usize,
    /// Bytes compressed so far, the counter `t` of the next compression.
    t: u64,
}

impl Default for Blake2s256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2s256 {
    pub fn new() -> Self {
        let mut h = IV;
        h[0] ^= PARAM_BLOCK_WORD0;
        Self {
            h,
            buf: [0u8; BLOCK_BYTES],
            buf_len: 0,
            t: 0,
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let mut data = data.as_ref();
        while !data.is_empty() {
            if self.buf_len == BLOCK_BYTES {
                // A full buffer is compressed only once more input follows:
                // the last block, full or not, is compressed by `finalize`
                // with the last-block flag.
                self.t += BLOCK_BYTES as u64;
                let block = self.buf;
                compress_block(&mut self.h, &block, self.t, false);
                self.buf_len = 0;
            }
            let take = (BLOCK_BYTES - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
        }
    }

    pub fn finalize(mut self) -> [u8; DIGEST_BYTES] {
        self.t += self.buf_len as u64;
        self.buf[self.buf_len..].fill(0);
        let block = self.buf;
        compress_block(&mut self.h, &block, self.t, true);
        let mut out = [0u8; DIGEST_BYTES];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.h) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    pub fn digest(data: impl AsRef<[u8]>) -> [u8; DIGEST_BYTES] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// One compression of a 64-byte block: the block as 16 little-endian u32
/// words, `t` as its two 32-bit halves.
fn compress_block(h: &mut [u32; 8], block: &[u8; BLOCK_BYTES], t: u64, last: bool) {
    let mut m = [0u32; 16];
    for (word, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    let t = [t as u32, (t >> 32) as u32];
    compress_f(h, &m, &t, last);
}

/// The compression function F: on the ZiSK target the `blake2sf` precompile
/// through the guest hook, elsewhere the software function.
#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
#[inline]
fn compress_f(h: &mut [u32; 8], m: &[u32; 16], t: &[u32; 2], f: bool) {
    // SAFETY: the pointers reference exactly the 8-, 16- and 2-word arrays
    // the hook reads and writes.
    unsafe { super::ffi::blake2s_compress_c(h.as_mut_ptr(), m.as_ptr(), t.as_ptr(), f as u8) }
}

#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
#[inline]
fn compress_f(h: &mut [u32; 8], m: &[u32; 16], t: &[u32; 2], f: bool) {
    software::compress(h, m, t, f);
}

/// Software RFC 7693 compression function F, the reference for what the
/// `blake2sf` precompile computes.
#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
pub mod software {
    use super::IV;

    /// Message word permutation per round (RFC 7693, section 2.7).
    const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    /// The mixing function G with the BLAKE2s rotation constants 16, 12, 8, 7.
    #[inline]
    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }

    /// F(h, m, t, f): initialise the 16-word working vector from `h`, the IV,
    /// the counter and the flag, run the ten rounds, and fold `v` back into
    /// `h`.
    pub fn compress(h: &mut [u32; 8], m: &[u32; 16], t: &[u32; 2], f: bool) {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(h);
        v[8..12].copy_from_slice(&IV[..4]);
        v[12] = t[0] ^ IV[4];
        v[13] = t[1] ^ IV[5];
        v[14] = if f { !IV[6] } else { IV[6] };
        v[15] = IV[7];

        for s in SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Digest;

    fn reference(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = blake2::Blake2s256::new();
        for part in parts {
            h.update(part);
        }
        h.finalize().into()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect()
    }

    /// RFC 7693, Appendix B: BLAKE2s-256("abc") is one final block with
    /// t = 3, so the software F alone must produce the published digest.
    #[test]
    fn software_f_reproduces_the_rfc7693_abc_vector() {
        let mut h = IV;
        h[0] ^= PARAM_BLOCK_WORD0;
        let mut m = [0u32; 16];
        m[0] = 0x0063_6261; // "abc", little-endian
        software::compress(&mut h, &m, &[3, 0], true);
        let mut digest = [0u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(h) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        assert_eq!(
            alloy_primitives::hex::encode(digest),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
    }

    /// The empty message is a single zero block with t = 0 and the last-block
    /// flag; the published digest pins the parameter block and the padding.
    #[test]
    fn empty_input_matches_the_published_digest() {
        assert_eq!(
            alloy_primitives::hex::encode(Blake2s256::digest([])),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
        assert_eq!(Blake2s256::digest([]), reference(&[&[]]));
    }

    /// Block boundaries: below one block, exactly one block (compressed only
    /// at finalize), one byte over (the first block compressed on the way,
    /// the one-byte tail padded), and multi-block inputs.
    #[test]
    fn matches_the_blake2_crate_across_block_boundaries() {
        for len in [1usize, 3, 63, 64, 65, 127, 128, 129, 200, 1000] {
            let data = pattern(len);
            assert_eq!(Blake2s256::digest(&data), reference(&[&data]), "len {len}");
        }
    }

    /// Splitting the input across `update` calls never changes the digest,
    /// including splits on and around the block boundary.
    #[test]
    fn incremental_updates_match_one_shot() {
        let data = pattern(200);
        for split in [0usize, 1, 63, 64, 65, 128, 199, 200] {
            let mut h = Blake2s256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), reference(&[&data]), "split {split}");
        }
        let mut h = Blake2s256::new();
        for byte in &data {
            h.update([*byte]);
        }
        assert_eq!(h.finalize(), reference(&[&data]));
    }

    /// The two-hash node shape of `block_roots::blake2s_compress`:
    /// `blake2s(left32 ‖ right32)` fed as two updates.
    #[test]
    fn two_hash_node_shape_matches_the_blake2_crate() {
        let lhs = [0x11u8; 32];
        let rhs = pattern(32);
        let mut h = Blake2s256::new();
        h.update(lhs);
        h.update(&rhs);
        assert_eq!(h.finalize(), reference(&[&lhs, &rhs]));
    }

    /// The `account_props` bytecode-hash shape: code, then padding, then the
    /// artifacts, as three updates over a multi-block preimage.
    #[test]
    fn bytecode_hash_shape_matches_the_blake2_crate() {
        let code = pattern(101);
        let padding = [0u8; 3];
        let artifacts = pattern(16);
        let mut h = Blake2s256::new();
        h.update(&code);
        h.update(padding);
        h.update(&artifacts);
        assert_eq!(h.finalize(), reference(&[&code, &padding, &artifacts]));
    }
}
