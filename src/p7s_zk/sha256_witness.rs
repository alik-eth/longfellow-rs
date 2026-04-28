//! Off-circuit SHA-256 witness builder for the p7s hash circuit.
//!
//! Mirrors C++ `vendor/longfellow-zk/lib/circuits/sha/flatsha256_witness.cc`
//! and `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:1614-1660`.
//!
//! The p7s hash circuit is `Field2_128`, and per `kP7sPluckerBits = 2`
//! (vendor `lib/circuits/p7s/p7s_hash.h:30`) every 32-bit witness u32 packs
//! into 16 field elements via `BitPlucker<2, Field2_128>`.
//!
//! The struct stores raw `u32`s exactly as C++ `BlockWitness` does. The dense
//! filler is then driven through [`push_sha_padded_bytes`] /
//! [`push_sha_block_witnesses`] in the order matching the in-circuit
//! `vinput<W>` declaration order in `build_hash_circuit()`.

use crate::{
    fields::{FieldElement, field2_128::Field2_128},
    mdoc_zk::bit_plucker::BitPlucker,
};
use alloc::{vec, vec::Vec};

/// Packed-elements-per-u32 under `BitPlucker<2, Field2_128>`.
///
/// `kP7sPluckerBits = 2` (vendor `p7s_hash.h:30`); 32 / 2 = 16.
const PACK_PER_U32: usize = 32 / 2;

/// Initial SHA-256 hash value (FIPS 180-4 § 5.3.3).
const INITIAL_HASH_VALUE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (FIPS 180-4 § 4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Per-block raw-u32 witnesses, mirror of C++ `FlatSHA256Witness::BlockWitness`.
#[derive(Clone, Debug)]
pub(crate) struct ShaBlockWitness {
    /// `outw[48]` — message_schedule[16..64].
    pub(crate) outw: [u32; 48],
    /// `oute[64]` — value of e at each of the 64 rounds.
    pub(crate) oute: [u32; 64],
    /// `outa[64]` — value of a at each of the 64 rounds.
    pub(crate) outa: [u32; 64],
    /// `h1[8]` — intermediate hash value after this block.
    pub(crate) h1: [u32; 8],
}

impl ShaBlockWitness {
    fn zero() -> Self {
        Self {
            outw: [0; 48],
            oute: [0; 64],
            outa: [0; 64],
            h1: [0; 8],
        }
    }
}

/// Off-circuit SHA-256 witness, mirror of C++ `ShaWitness<kMaxBlocks>` template.
#[derive(Clone, Debug)]
pub(crate) struct ShaWitness {
    /// `numb` — exact number of SHA blocks needed (≤ `MAX_BLOCKS`).
    pub(crate) numb: u8,
    /// `padded_in[64 * MAX_BLOCKS]` — fully-padded SHA input, zero-tail to MAX_BLOCKS.
    pub(crate) padded_in: Vec<u8>,
    /// `bw[MAX_BLOCKS]` — per-block intermediate witnesses for the entire fixed window.
    pub(crate) bw: Vec<ShaBlockWitness>,
    /// `MAX_BLOCKS` constant baked into this witness instance.
    pub(crate) max_blocks: usize,
    /// Final SHA-256 digest (BE byte order).
    pub(crate) digest: [u8; 32],
}

/// Compute an off-circuit SHA-256 witness for `raw_bytes`, padding to `max_blocks`.
///
/// Mirrors C++ `compute_sha_witness<kMaxBlocks>` /
/// `FlatSHA256Witness::transform_and_witness_message`. The fixed-window padding
/// behavior is identical: append `0x80`, zero-pad, BE u64 length-bits, then zero-
/// fill out to `64 * max_blocks` bytes. `numb` records the exact number of blocks
/// containing message bytes.
pub(crate) fn compute_sha_witness(raw_bytes: &[u8], max_blocks: usize) -> ShaWitness {
    let n = raw_bytes.len();
    // ceil((n + 9) / 64) — exact block count after padding.
    let numb_usize = (n + 9 + 63) / 64;
    assert!(
        numb_usize <= max_blocks,
        "SHA input too long: needs {numb_usize} blocks, max is {max_blocks}",
    );
    let numb = u8::try_from(numb_usize).expect("block count fits in u8");

    let total_bytes = 64 * max_blocks;
    let mut padded = vec![0u8; total_bytes];
    padded[..n].copy_from_slice(raw_bytes);
    padded[n] = 0x80;
    let length_bits = (n as u64) * 8;
    let length_offset = numb_usize * 64 - 8;
    padded[length_offset..length_offset + 8].copy_from_slice(&length_bits.to_be_bytes());

    // Compute per-block witnesses for ALL max_blocks (zero-tail blocks too — the
    // in-circuit SHA processes all blocks regardless of `numb`, with `numb`
    // selecting the digest output via a downstream mux).
    let mut bw: Vec<ShaBlockWitness> = (0..max_blocks).map(|_| ShaBlockWitness::zero()).collect();
    let mut h: [u32; 8] = INITIAL_HASH_VALUE;
    for bl in 0..max_blocks {
        let mut data = [0u32; 16];
        for (i, slot) in data.iter_mut().enumerate() {
            let offset = bl * 64 + i * 4;
            *slot = u32::from_be_bytes(padded[offset..offset + 4].try_into().unwrap());
        }
        transform_and_witness_block(&data, &h, &mut bw[bl]);
        h = bw[bl].h1;
    }

    let digest_bw_index = numb_usize - 1;
    let mut digest = [0u8; 32];
    for (i, h_word) in bw[digest_bw_index].h1.iter().enumerate() {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&h_word.to_be_bytes());
    }

    ShaWitness {
        numb,
        padded_in: padded,
        bw,
        max_blocks,
        digest,
    }
}

/// Single-block transform that records the per-round witness values.
///
/// Mirror of C++ `FlatSHA256Witness::transform_and_witness_block`.
fn transform_and_witness_block(input: &[u32; 16], h0: &[u32; 8], out: &mut ShaBlockWitness) {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(input);
    for i in 16..64 {
        w[i] = lower_sigma_1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(lower_sigma_0(w[i - 15]))
            .wrapping_add(w[i - 16]);
        out.outw[i - 16] = w[i];
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *h0;
    for t in 0..64 {
        let t1 = h
            .wrapping_add(upper_sigma_1(e))
            .wrapping_add(choice(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = upper_sigma_0(a).wrapping_add(majority(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        out.oute[t] = e;
        out.outa[t] = a;
    }

    out.h1[0] = h0[0].wrapping_add(a);
    out.h1[1] = h0[1].wrapping_add(b);
    out.h1[2] = h0[2].wrapping_add(c);
    out.h1[3] = h0[3].wrapping_add(d);
    out.h1[4] = h0[4].wrapping_add(e);
    out.h1[5] = h0[5].wrapping_add(f);
    out.h1[6] = h0[6].wrapping_add(g);
    out.h1[7] = h0[7].wrapping_add(h);
}

fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
fn upper_sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn upper_sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
fn lower_sigma_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
fn lower_sigma_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Push a single byte LSB-first as 8 field-element wires.
///
/// Mirror of C++ `push_v8(filler, x, Fs)` at `p7s_zk.cc:1559`.
pub(crate) fn push_v8(out: &mut Vec<Field2_128>, x: u8) {
    for j in 0..8 {
        let bit = (x >> j) & 1;
        out.push(if bit == 1 {
            Field2_128::ONE
        } else {
            Field2_128::ZERO
        });
    }
}

/// Push a `K`-bit unsigned integer LSB-first as `K` field-element wires.
///
/// Mirror of C++ `push_uint(filler, x, k, Fs)` at `p7s_zk.cc:1564`.
pub(crate) fn push_uint(out: &mut Vec<Field2_128>, value: u64, k: usize) {
    for j in 0..k {
        let bit = (value >> j) & 1;
        out.push(if bit == 1 {
            Field2_128::ONE
        } else {
            Field2_128::ZERO
        });
    }
}

/// Push the SHA-padded message bytes (`64 * MAX_BLOCKS` bytes) into the dense filler.
///
/// Mirror of C++ `push_sha_padded_bytes<kMaxBlocks>` at `p7s_zk.cc:1631-1635`.
pub(crate) fn push_sha_padded_bytes(out: &mut Vec<Field2_128>, sw: &ShaWitness) {
    for &byte in &sw.padded_in {
        push_v8(out, byte);
    }
}

/// Push per-block intermediate witnesses, packing each u32 via
/// `BitPlucker<2, Field2_128>`.
///
/// Order, per block:
///   1. `outw[0..48]` — 48 packed_v32 entries
///   2. for k in 0..64: `oute[k]`, then `outa[k]` — 128 packed_v32 entries total
///   3. `h1[0..8]` — 8 packed_v32 entries
///
/// Each packed_v32 expands into [`PACK_PER_U32`] field elements LSB-first.
///
/// Mirror of C++ `push_sha_block_witnesses<kMaxBlocks>` at `p7s_zk.cc:1638-1657`.
pub(crate) fn push_sha_block_witnesses(out: &mut Vec<Field2_128>, sw: &ShaWitness) {
    let plucker = BitPlucker::<2, Field2_128>::new();
    let mut buf = [Field2_128::ZERO; PACK_PER_U32];
    for bw in &sw.bw {
        for &w in &bw.outw {
            plucker.encode_u32_array(&[w], &mut buf);
            out.extend_from_slice(&buf);
        }
        for k in 0..64 {
            plucker.encode_u32_array(&[bw.oute[k]], &mut buf);
            out.extend_from_slice(&buf);
            plucker.encode_u32_array(&[bw.outa[k]], &mut buf);
            out.extend_from_slice(&buf);
        }
        for &h_word in &bw.h1 {
            plucker.encode_u32_array(&[h_word], &mut buf);
            out.extend_from_slice(&buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn digest_matches_sha2_crate_for_small_input() {
        let input = b"abc";
        let sw = compute_sha_witness(input, 1);
        let expected = <[u8; 32]>::from(Sha256::digest(input));
        assert_eq!(sw.digest, expected);
        assert_eq!(sw.numb, 1);
    }

    #[test]
    fn digest_matches_sha2_crate_for_two_block_input() {
        // 65 bytes — straddles the 56-byte single-block padding cap, forces 2 blocks.
        let input = [0xa5u8; 65];
        let sw = compute_sha_witness(&input, 2);
        let expected = <[u8; 32]>::from(Sha256::digest(input));
        assert_eq!(sw.digest, expected);
        assert_eq!(sw.numb, 2);
        assert_eq!(sw.padded_in.len(), 128);
    }

    #[test]
    fn digest_matches_sha2_crate_for_max_padded_input() {
        // Single-block "exactly 55 bytes" boundary — last byte fits before length suffix.
        let input = [0xffu8; 55];
        let sw = compute_sha_witness(&input, 1);
        let expected = <[u8; 32]>::from(Sha256::digest(input));
        assert_eq!(sw.digest, expected);
        assert_eq!(sw.numb, 1);
    }

    #[test]
    fn padded_in_zero_tail_for_excess_blocks() {
        let input = b"hi";
        let sw = compute_sha_witness(input, 4);
        // Bytes 0..2 are message; byte 2 is 0x80; bytes 56..64 hold length BE.
        // All bytes in blocks 1,2,3 must be zero.
        for byte in &sw.padded_in[64..] {
            assert_eq!(*byte, 0);
        }
        assert_eq!(sw.numb, 1);
    }

    #[test]
    fn push_v8_lsb_first_byte_0xa5() {
        // 0xA5 = 0b10100101 → LSB-first wires = [1, 0, 1, 0, 0, 1, 0, 1]
        let mut out = Vec::new();
        push_v8(&mut out, 0xa5);
        let expected: [Field2_128; 8] = [
            Field2_128::ONE,
            Field2_128::ZERO,
            Field2_128::ONE,
            Field2_128::ZERO,
            Field2_128::ZERO,
            Field2_128::ONE,
            Field2_128::ZERO,
            Field2_128::ONE,
        ];
        assert_eq!(out, expected.to_vec());
    }

    #[test]
    fn push_uint_lsb_first_11_bits() {
        // 0b101 0101 0101 = 1365 → LSB-first wires (11 bits) =
        // [1,0,1,0,1,0,1,0,1,0,1]
        let mut out = Vec::new();
        push_uint(&mut out, 1365, 11);
        let expected = [1u8, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1].map(|bit| {
            if bit == 1 {
                Field2_128::ONE
            } else {
                Field2_128::ZERO
            }
        });
        assert_eq!(out, expected.to_vec());
    }

    #[test]
    fn padded_bytes_count_matches_max_blocks() {
        let sw = compute_sha_witness(b"abc", 3);
        let mut out: Vec<Field2_128> = Vec::new();
        push_sha_padded_bytes(&mut out, &sw);
        assert_eq!(out.len(), 64 * 3 * 8);
    }

    #[test]
    fn block_witnesses_count_matches_packed_v32() {
        let sw = compute_sha_witness(b"abc", 2);
        let mut out: Vec<Field2_128> = Vec::new();
        push_sha_block_witnesses(&mut out, &sw);
        // Per block: (48 outw + 64*2 oute/outa + 8 h1) * PACK_PER_U32 = (48 + 128 + 8) * 16
        let per_block = (48 + 64 * 2 + 8) * PACK_PER_U32;
        assert_eq!(out.len(), per_block * 2);
    }
}
