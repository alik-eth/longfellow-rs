//! Per-invariant witness fillers for the p7s hash circuit.
//!
//! Mirrors C++ `push_invariant{4,5,6,10,13}_witness` at
//! `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:1667-1729`.
//!
//! Each invariant covers a JSON-binding equality check inside the in-circuit
//! signed-content scan. The fill order mirrors the C++ helpers byte-for-byte.

use crate::{
    fields::field2_128::Field2_128,
    p7s_zk::sha256_witness::{push_uint, push_v8},
};
use alloc::vec::Vec;

/// log2(kMaxSignedContent = 1024) — used for every `json_*_offset` width.
///
/// C++: `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:431`.
pub(crate) const SIGNED_CONTENT_LOG_N: usize = 10;

/// Hex-encoded P-256 uncompressed pubkey length (1 + 64 = 65 bytes → 130 chars).
///
/// C++: `vendor/longfellow-zk/lib/circuits/p7s/p7s_circuit.h:26`.
pub(crate) const PK_HEX_LEN: usize = 130;

/// Hex-encoded 32-byte nonce length (32 → 64 chars).
///
/// C++: `vendor/longfellow-zk/lib/circuits/p7s/p7s_circuit.h:33`.
pub(crate) const NONCE_HEX_LEN: usize = 64;

/// Hex-encoded 32-byte holder_seed_commit length (32 → 64 chars).
///
/// C++: `vendor/longfellow-zk/lib/circuits/p7s/p7s_circuit.h:177`.
pub(crate) const HOLDER_SEED_COMMIT_HEX_LEN: usize = 64;

/// Decoded holder_seed_commit byte-length (32).
///
/// C++: `vendor/longfellow-zk/lib/circuits/p7s/p7s_circuit.h:178`.
pub(crate) const HOLDER_SEED_COMMIT_BYTES: usize = 32;

/// Convert a single ASCII hex character to its 4-bit nibble value.
///
/// Mirrors C++ `nibble_of` at `p7s_zk.cc:1660`. Non-hex inputs map to 0
/// (consistent with the C++ which has identical fall-through; the in-circuit
/// hex_decode gadget recomputes nibbles, so a host-side typo would fail the
/// in-circuit byte-equality check downstream rather than corrupting silently).
fn nibble_of(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Invariant 4 — JSON pubkey hex anchor.
///
/// Push order:
///   1. `json_pk_offset` as a `SIGNED_CONTENT_LOG_N`-bit unsigned integer
///   2. `pk_hex[0..PK_HEX_LEN]` — each hex char as 8 LSB-first bits via push_v8
///   3. `nibble_of(pk_hex[0..PK_HEX_LEN])` — each derived nibble as 8 LSB-first bits
///
/// C++: `push_invariant4_witness` at `p7s_zk.cc:1667-1676`.
pub(crate) fn push_invariant4_witness(
    out: &mut Vec<Field2_128>,
    json_pk_offset: u32,
    pk_hex: &[u8; PK_HEX_LEN],
) {
    push_uint(out, u64::from(json_pk_offset), SIGNED_CONTENT_LOG_N);
    for &c in pk_hex.iter() {
        push_v8(out, c);
    }
    for &c in pk_hex.iter() {
        push_v8(out, nibble_of(c));
    }
}

/// Invariant 5 — JSON nonce hex anchor.
///
/// Same shape as invariant 4 but for the 64-char nonce_hex.
///
/// C++: `push_invariant5_witness` at `p7s_zk.cc:1678-1689`.
pub(crate) fn push_invariant5_witness(
    out: &mut Vec<Field2_128>,
    json_nonce_offset: u32,
    nonce_hex: &[u8; NONCE_HEX_LEN],
) {
    push_uint(out, u64::from(json_nonce_offset), SIGNED_CONTENT_LOG_N);
    for &c in nonce_hex.iter() {
        push_v8(out, c);
    }
    for &c in nonce_hex.iter() {
        push_v8(out, nibble_of(c));
    }
}

/// Invariant 6 — JSON context offset.
///
/// Push order: `json_context_offset` as a SIGNED_CONTENT_LOG_N-bit unsigned int.
///
/// C++: `push_invariant6_witness` at `p7s_zk.cc:1691-1694`.
pub(crate) fn push_invariant6_witness(out: &mut Vec<Field2_128>, json_context_offset: u32) {
    push_uint(out, u64::from(json_context_offset), SIGNED_CONTENT_LOG_N);
}

/// Invariant 10 — JSON declaration offset.
///
/// Push order: `json_declaration_offset` as a SIGNED_CONTENT_LOG_N-bit unsigned int.
///
/// C++: `push_invariant10_witness` at `p7s_zk.cc:1696-1699`.
pub(crate) fn push_invariant10_witness(out: &mut Vec<Field2_128>, json_declaration_offset: u32) {
    push_uint(out, u64::from(json_declaration_offset), SIGNED_CONTENT_LOG_N);
}

/// Invariant 13 — JSON holder_seed_commit hex anchor + decoded bytes.
///
/// Push order:
///   1. `json_holder_seed_commit_offset` as a SIGNED_CONTENT_LOG_N-bit unsigned int
///   2. `holder_seed_commit_hex[0..HOLDER_SEED_COMMIT_HEX_LEN]` — raw hex chars (push_v8 each)
///   3. `nibble_of(holder_seed_commit_hex[0..HOLDER_SEED_COMMIT_HEX_LEN])` — derived nibbles
///   4. `holder_seed_commit_bytes[0..HOLDER_SEED_COMMIT_BYTES]` — decoded bytes
///      (each byte = (high nibble << 4) | low nibble), so the in-circuit
///      hex_decode gadget's byte-equality wires line up with the host's
///      enroll_commit_target check.
///
/// C++: `push_invariant13_witness` at `p7s_zk.cc:1710-1729`.
pub(crate) fn push_invariant13_witness(
    out: &mut Vec<Field2_128>,
    json_holder_seed_commit_offset: u32,
    holder_seed_commit_hex: &[u8; HOLDER_SEED_COMMIT_HEX_LEN],
) {
    push_uint(
        out,
        u64::from(json_holder_seed_commit_offset),
        SIGNED_CONTENT_LOG_N,
    );
    for &c in holder_seed_commit_hex.iter() {
        push_v8(out, c);
    }
    for &c in holder_seed_commit_hex.iter() {
        push_v8(out, nibble_of(c));
    }
    for i in 0..HOLDER_SEED_COMMIT_BYTES {
        let hi = nibble_of(holder_seed_commit_hex[2 * i]);
        let lo = nibble_of(holder_seed_commit_hex[2 * i + 1]);
        push_v8(out, (hi << 4) | lo);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::FieldElement;

    fn count_one_bits(buf: &[Field2_128]) -> usize {
        buf.iter().filter(|f| **f == Field2_128::ONE).count()
    }

    fn count_zero_bits(buf: &[Field2_128]) -> usize {
        buf.iter().filter(|f| **f == Field2_128::ZERO).count()
    }

    #[test]
    fn invariant6_pushes_only_offset_bits() {
        let mut out = Vec::new();
        push_invariant6_witness(&mut out, 42);
        assert_eq!(out.len(), SIGNED_CONTENT_LOG_N);
        // 42 = 0b0000101010 → LSB-first 10 bits = [0,1,0,1,0,1,0,0,0,0]
        let expected: [u8; 10] = [0, 1, 0, 1, 0, 1, 0, 0, 0, 0];
        for (i, &bit) in expected.iter().enumerate() {
            let want = if bit == 1 { Field2_128::ONE } else { Field2_128::ZERO };
            assert_eq!(out[i], want, "bit {i}");
        }
    }

    #[test]
    fn invariant10_pushes_only_offset_bits() {
        let mut out = Vec::new();
        push_invariant10_witness(&mut out, 1023);
        assert_eq!(out.len(), SIGNED_CONTENT_LOG_N);
        // 1023 = 0b1111111111 — all 10 wires must be ONE
        for f in out {
            assert_eq!(f, Field2_128::ONE);
        }
    }

    #[test]
    fn invariant4_lengths_total_correct() {
        let mut out = Vec::new();
        let pk_hex = [b'0'; PK_HEX_LEN];
        push_invariant4_witness(&mut out, 0, &pk_hex);
        // SIGNED_CONTENT_LOG_N + PK_HEX_LEN * 8 (raw chars) + PK_HEX_LEN * 8 (nibbles)
        let expected = SIGNED_CONTENT_LOG_N + PK_HEX_LEN * 8 + PK_HEX_LEN * 8;
        assert_eq!(out.len(), expected);
        // offset = 0 → all zero in offset region
        for i in 0..SIGNED_CONTENT_LOG_N {
            assert_eq!(out[i], Field2_128::ZERO);
        }
        // pk_hex region — char '0' = 0x30 → LSB-first bits = [0,0,0,0,1,1,0,0]
        // Per char: 2 ONEs out of 8 (bits 4 and 5); over PK_HEX_LEN chars: 2 * 130 = 260 ONEs.
        let raw_chars_region = &out[SIGNED_CONTENT_LOG_N..SIGNED_CONTENT_LOG_N + PK_HEX_LEN * 8];
        assert_eq!(count_one_bits(raw_chars_region), 2 * PK_HEX_LEN);
        // nibble region — nibble_of('0') = 0 → all bits ZERO over the trailing PK_HEX_LEN * 8 wires.
        let nibbles_region = &out[SIGNED_CONTENT_LOG_N + PK_HEX_LEN * 8..];
        assert_eq!(count_zero_bits(nibbles_region), PK_HEX_LEN * 8);
    }

    #[test]
    fn invariant5_lengths_total_correct() {
        let mut out = Vec::new();
        let nonce_hex = [b'a'; NONCE_HEX_LEN];
        push_invariant5_witness(&mut out, 0, &nonce_hex);
        let expected = SIGNED_CONTENT_LOG_N + NONCE_HEX_LEN * 8 + NONCE_HEX_LEN * 8;
        assert_eq!(out.len(), expected);
    }

    #[test]
    fn invariant13_lengths_total_correct() {
        let mut out = Vec::new();
        let hex = [b'f'; HOLDER_SEED_COMMIT_HEX_LEN];
        push_invariant13_witness(&mut out, 0, &hex);
        // SIGNED_CONTENT_LOG_N + HEX_LEN * 8 (raw) + HEX_LEN * 8 (nibbles) + BYTES * 8 (decoded)
        let expected = SIGNED_CONTENT_LOG_N
            + HOLDER_SEED_COMMIT_HEX_LEN * 8
            + HOLDER_SEED_COMMIT_HEX_LEN * 8
            + HOLDER_SEED_COMMIT_BYTES * 8;
        assert_eq!(out.len(), expected);
        // hex='f' → nibble = 0xF, decoded byte = 0xFF (all ones).
        let decoded_region = &out[expected - HOLDER_SEED_COMMIT_BYTES * 8..];
        assert_eq!(count_one_bits(decoded_region), HOLDER_SEED_COMMIT_BYTES * 8);
    }

    #[test]
    fn nibble_of_handles_all_hex_classes() {
        assert_eq!(nibble_of(b'0'), 0);
        assert_eq!(nibble_of(b'9'), 9);
        assert_eq!(nibble_of(b'a'), 10);
        assert_eq!(nibble_of(b'f'), 15);
        assert_eq!(nibble_of(b'A'), 10);
        assert_eq!(nibble_of(b'F'), 15);
        assert_eq!(nibble_of(b'g'), 0); // out-of-range → 0 (matches C++)
        assert_eq!(nibble_of(b'!'), 0);
    }
}
