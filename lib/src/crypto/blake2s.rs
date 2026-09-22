//! BLAKE2s-256 on the `blake2sf` permutation.
//!
//! `blake2sf` is the ten-round BLAKE2s permutation of the 16-word working
//! vector — the compression function F of RFC 7693, section 3.2, without its
//! initialisation and `h ^= v_lo ^ v_hi` feed-forward. ZiSK exposes exactly
//! that as a precompile over eight u64 slots, each holding two little-endian
//! u32 words (word `2i` low, `2i + 1` high). On the ZiSK target it is reached
//! through the guest's `blake2sf_c` hook (see `ffi.rs`); elsewhere it is
//! [`software::blake2sf`]. Everything around the permutation — the parameter
//! block folded into the IV, the counter and last-block flag, the
//! feed-forward — is done here on the same u64 slots, so nothing is repacked
//! between the message bytes and the precompile.
//!
//! [`node_hash`] is the one-block `blake2s(left32 ‖ right32)` of every Merkle
//! node in `merkle` and `block_roots`; it skips the streaming hasher and is
//! used on every target. [`Blake2s256`] is the streaming hasher for the other
//! preimages (tree leaves, bytecode); its production callers use it on the
//! ZiSK target only and keep the `blake2` crate off-target, which the tests
//! here compare against.

/// The BLAKE2s initialization vector: the first 32 bits of the fractional
/// parts of the square roots of the first eight primes.
pub const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
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

/// Bytes per u64 slot.
const SLOT_BYTES: usize = 8;
/// Slots of the working vector and of a message block (16 u32 words).
pub const BLOCK_SLOTS: usize = BLOCK_BYTES / SLOT_BYTES;
/// Slots of the chaining state `h` and of a digest (eight u32 words).
const DIGEST_SLOTS: usize = DIGEST_BYTES / SLOT_BYTES;

/// Two u32 words as one slot: `lo` in the low half, `hi` in the high half.
const fn slot(lo: u32, hi: u32) -> u64 {
    lo as u64 | ((hi as u64) << 32)
}

/// The IV as slots.
const IV_SLOTS: [u64; DIGEST_SLOTS] = [
    slot(IV[0], IV[1]),
    slot(IV[2], IV[3]),
    slot(IV[4], IV[5]),
    slot(IV[6], IV[7]),
];

/// `h` before the first block of an unkeyed 32-byte digest.
const INITIAL_STATE: [u64; DIGEST_SLOTS] = [
    IV_SLOTS[0] ^ PARAM_BLOCK_WORD0 as u64,
    IV_SLOTS[1],
    IV_SLOTS[2],
    IV_SLOTS[3],
];

/// Inverts `v[14]` (the low word of slot 7) on the last block.
const LAST_BLOCK_MASK: u64 = u32::MAX as u64;

/// `blake2s(lhs ‖ rhs)`: the Merkle node hash, one compression of the two
/// children as a single full block.
pub fn node_hash(lhs: &[u8; DIGEST_BYTES], rhs: &[u8; DIGEST_BYTES]) -> [u8; DIGEST_BYTES] {
    let (l, r) = (slots_of(lhs), slots_of(rhs));
    let m = [l[0], l[1], l[2], l[3], r[0], r[1], r[2], r[3]];
    let mut h = INITIAL_STATE;
    compress(&mut h, &m, BLOCK_BYTES as u64, true);
    bytes_of(&h)
}

/// A 32-byte value as little-endian slots.
///
/// An 8-aligned value is read as whole words. The ZiSK target has no
/// unaligned loads, so the byte-wise path stays for the rest; the reads are
/// volatile only so the compiler does not fold this path into that one
/// (which the target would lower back to byte loads).
#[inline]
fn slots_of(bytes: &[u8; DIGEST_BYTES]) -> [u64; DIGEST_SLOTS] {
    let p = bytes.as_ptr();
    #[cfg(target_endian = "little")]
    if p as usize % SLOT_BYTES == 0 {
        let p = p.cast::<u64>();
        // SAFETY: `bytes` is 32 readable bytes, aligned as checked, and every
        // bit pattern is a valid u64; little-endian makes the slot order the
        // byte order.
        return unsafe {
            [
                p.read_volatile(),
                p.add(1).read_volatile(),
                p.add(2).read_volatile(),
                p.add(3).read_volatile(),
            ]
        };
    }
    let mut slots = [0u64; DIGEST_SLOTS];
    for (i, slot) in slots.iter_mut().enumerate() {
        *slot = u64::from_le_bytes(
            bytes[i * SLOT_BYTES..(i + 1) * SLOT_BYTES]
                .try_into()
                .unwrap(),
        );
    }
    slots
}

/// Slots to little-endian bytes, the mirror of [`slots_of`].
#[inline]
fn write_bytes(slots: &[u64; DIGEST_SLOTS], out: &mut [u8; DIGEST_BYTES]) {
    let p = out.as_mut_ptr();
    #[cfg(target_endian = "little")]
    if p as usize % SLOT_BYTES == 0 {
        let p = p.cast::<u64>();
        // SAFETY: `out` is 32 writable bytes, aligned as checked.
        unsafe {
            for (i, slot) in slots.iter().enumerate() {
                p.add(i).write_volatile(*slot);
            }
        }
        return;
    }
    for (i, slot) in slots.iter().enumerate() {
        out[i * SLOT_BYTES..(i + 1) * SLOT_BYTES].copy_from_slice(&slot.to_le_bytes());
    }
}

/// Slots to little-endian bytes.
#[inline]
fn bytes_of(slots: &[u64; DIGEST_SLOTS]) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    write_bytes(slots, &mut out);
    out
}

/// A message block, aligned so its slots load as whole words.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct Block([u8; BLOCK_BYTES]);

impl Block {
    #[inline]
    fn slots(&self) -> [u64; BLOCK_SLOTS] {
        let mut m = [0u64; BLOCK_SLOTS];
        for (i, slot) in m.iter_mut().enumerate() {
            *slot = u64::from_le_bytes(
                self.0[i * SLOT_BYTES..(i + 1) * SLOT_BYTES]
                    .try_into()
                    .unwrap(),
            );
        }
        m
    }
}

/// BLAKE2s-256 streaming hasher (unkeyed).
#[derive(Clone)]
pub struct Blake2s256 {
    h: [u64; DIGEST_SLOTS],
    buf: Block,
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
        Self {
            h: INITIAL_STATE,
            buf: Block([0u8; BLOCK_BYTES]),
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
                let m = self.buf.slots();
                compress(&mut self.h, &m, self.t, false);
                self.buf_len = 0;
            }
            let take = (BLOCK_BYTES - self.buf_len).min(data.len());
            self.buf.0[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
        }
    }

    pub fn finalize(mut self) -> [u8; DIGEST_BYTES] {
        self.t += self.buf_len as u64;
        self.buf.0[self.buf_len..].fill(0);
        let m = self.buf.slots();
        compress(&mut self.h, &m, self.t, true);
        bytes_of(&self.h)
    }

    pub fn digest(data: impl AsRef<[u8]>) -> [u8; DIGEST_BYTES] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// The compression function F(h, m, t, f) on slots: initialise the working
/// vector from `h`, the IV, the counter and the flag, run `blake2sf`, and
/// fold `v` back into `h`.
#[inline]
fn compress(h: &mut [u64; DIGEST_SLOTS], m: &[u64; BLOCK_SLOTS], t: u64, last: bool) {
    let mut v = [
        h[0],
        h[1],
        h[2],
        h[3],
        IV_SLOTS[0],
        IV_SLOTS[1],
        IV_SLOTS[2] ^ t,
        IV_SLOTS[3] ^ if last { LAST_BLOCK_MASK } else { 0 },
    ];
    blake2sf(&mut v, m);
    for i in 0..DIGEST_SLOTS {
        h[i] ^= v[i] ^ v[i + DIGEST_SLOTS];
    }
}

/// The `blake2sf` permutation: on the ZiSK target the precompile through
/// the guest hook, elsewhere the software function.
#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
#[inline]
fn blake2sf(v: &mut [u64; BLOCK_SLOTS], m: &[u64; BLOCK_SLOTS]) {
    // SAFETY: both arrays are exactly the eight 8-aligned slots the hook
    // reads and writes.
    unsafe { super::ffi::blake2sf_c(v.as_mut_ptr(), m.as_ptr()) }
}

#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
#[inline]
fn blake2sf(v: &mut [u64; BLOCK_SLOTS], m: &[u64; BLOCK_SLOTS]) {
    software::blake2sf(v, m);
}

/// Software `blake2sf`, the reference for what the precompile computes.
#[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
pub mod software {
    use super::BLOCK_SLOTS;

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

    fn words(slots: &[u64; BLOCK_SLOTS]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (i, slot) in slots.iter().enumerate() {
            words[2 * i] = *slot as u32;
            words[2 * i + 1] = (*slot >> 32) as u32;
        }
        words
    }

    /// The ten rounds over the working vector `v` with message block `m`,
    /// both as the precompile's u64 slots.
    pub fn blake2sf(v: &mut [u64; BLOCK_SLOTS], m: &[u64; BLOCK_SLOTS]) {
        let mut w = words(v);
        let m = words(m);
        for s in SIGMA {
            g(&mut w, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut w, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut w, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut w, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut w, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut w, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut w, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut w, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (i, slot) in v.iter_mut().enumerate() {
            *slot = super::slot(w[2 * i], w[2 * i + 1]);
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
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
            .collect()
    }

    /// RFC 7693, Appendix B: BLAKE2s-256("abc") is one final block with
    /// t = 3, so F over the software permutation alone must produce the
    /// published digest.
    #[test]
    fn f_reproduces_the_rfc7693_abc_vector() {
        let mut h = INITIAL_STATE;
        let mut m = [0u64; BLOCK_SLOTS];
        m[0] = 0x0063_6261; // "abc", little-endian, in the low word of slot 0
        compress(&mut h, &m, 3, true);
        assert_eq!(
            alloy_primitives::hex::encode(bytes_of(&h)),
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

    /// `node_hash` is `blake2s(left32 ‖ right32)`, the streaming hasher fed
    /// the same two halves, and the `blake2` crate.
    #[test]
    fn node_hash_matches_the_streaming_hasher_and_the_blake2_crate() {
        let cases: [([u8; 32], [u8; 32]); 3] = [
            ([0x11u8; 32], pattern(32).try_into().unwrap()),
            ([0u8; 32], [0u8; 32]),
            ([0xffu8; 32], pattern(32).try_into().unwrap()),
        ];
        for (lhs, rhs) in cases {
            let mut h = Blake2s256::new();
            h.update(lhs);
            h.update(rhs);
            let streamed = h.finalize();
            assert_eq!(node_hash(&lhs, &rhs), streamed);
            assert_eq!(streamed, reference(&[&lhs, &rhs]));
        }
    }

    /// The children of a node arrive at every alignment (`B256` is
    /// byte-aligned); the whole-word fast path and the byte-wise path of
    /// `slots_of` must agree.
    #[test]
    fn node_hash_is_independent_of_the_children_alignment() {
        #[repr(C, align(8))]
        struct Aligned([u8; 40]);
        let mut lhs = Aligned([0u8; 40]);
        let mut rhs = Aligned([0u8; 40]);
        lhs.0[..].copy_from_slice(&pattern(40));
        rhs.0[..].copy_from_slice(&pattern(80)[40..]);
        let aligned = node_hash(
            lhs.0[..32].try_into().unwrap(),
            rhs.0[..32].try_into().unwrap(),
        );
        assert_eq!(aligned, reference(&[&lhs.0[..32], &rhs.0[..32]]));
        for offset in 1..8 {
            let l: &[u8; 32] = lhs.0[offset..offset + 32].try_into().unwrap();
            let r: &[u8; 32] = rhs.0[offset..offset + 32].try_into().unwrap();
            assert_ne!(
                l.as_ptr() as usize % 8,
                0,
                "offset {offset} is not unaligned"
            );
            assert_eq!(node_hash(l, r), reference(&[l, r]), "offset {offset}");
        }
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
