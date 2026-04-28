//! Reference MAC over GF(2^128) — Rust port of C++
//! `vendor/longfellow-zk/lib/circuits/mac/mac_reference.h`
//!
//! The p7s circuit binds 4 messages across the hash + sig field split
//! (`e = SHA-256(cert_tbs)`, `e2 = SHA-256(signedAttrs)`, cert SPKI X,
//! cert SPKI Y) via a MAC gadget: each 256-bit message is split into
//! two 128-bit halves; for each half, the prover commits an `ap[i]`
//! random share; the verifier samples a fresh `av` random challenge
//! from the post-commit transcript; the MAC is `mac[i] = (av + ap[i]) * msg_half_i`.
//! Both circuits then assert this relation in-circuit, which lets the
//! sig-side prover bind a value that originated on the hash side and
//! vice versa without sharing wire space.
//!
//! This is the OFF-CIRCUIT reference implementation. The C++ vendor's
//! `MACReference<F>` lives in `mac_reference.h`; the in-circuit
//! `MAC<CB,Plucker>::verify_mac` lives in `circuits/mac/mac_circuit.h`.
//! Cross-language correctness rests on this off-circuit code matching
//! the C++ exactly.
//!
//! This module is the source-of-truth MAC for the pure-Rust p7s prover.
//! The Rust↔Rust prove/verify round-trip on the canonical v12 fixture
//! (Task #95 scope A) goes through this module; cross-language parity
//! against C++ is `#98`'s responsibility.
//!
//! Constant breakdown for p7s (from
//! `vendor/longfellow-zk/lib/circuits/p7s/sub/p7s_signature.h:75-99`):
//!   * `kMacMessagesCount = 4` (e, e2, spki_x, spki_y)
//!   * `kMacValuesPerMessage = 2` (low + high halves of the 256-bit msg)
//!   * `kTotalMacValues = 8`
//!   * `kMacMessageBytes = 32`

use crate::fields::{FieldElement, field2_128::Field2_128};
use alloc::vec::Vec;

/// 4 distinct 256-bit messages bound by p7s. Mirrors C++
/// `kMacMessagesCount`.
pub const MAC_MESSAGES_COUNT: usize = 4;
/// Each 256-bit message decomposes into 2 GF(2^128) halves.
pub const MAC_VALUES_PER_MESSAGE: usize = 2;
/// Total MAC values bound across both circuits.
pub const TOTAL_MAC_VALUES: usize = MAC_MESSAGES_COUNT * MAC_VALUES_PER_MESSAGE;
/// Bytes per bound message (always 32 in the p7s use-case).
pub const MAC_MESSAGE_BYTES: usize = 32;
/// Bytes per GF(2^128) half (16).
pub const FIELD2_128_BYTES: usize = 16;

// ---- Message indices, mirror p7s_signature.h:87-90. ----
/// Index of `e = SHA-256(cert_tbs)` in the macs/ap arrays.
pub const MAC_MSG_IDX_E: usize = 0;
/// Index of `e2 = SHA-256(signedAttrs_canonical)`.
pub const MAC_MSG_IDX_E2: usize = 1;
/// Index of cert_tbs SPKI X coordinate (LE-ordered).
pub const MAC_MSG_IDX_SPKI_X: usize = 2;
/// Index of cert_tbs SPKI Y coordinate (LE-ordered).
pub const MAC_MSG_IDX_SPKI_Y: usize = 3;

/// Sample `n` independent random GF(2^128) prover-share values via
/// `rand::rng()`. Mirrors C++ `MACReference::sample` — fills `n*16`
/// random bytes via the RNG, reinterprets as `n` LE-encoded
/// `Field2_128` elements (no rejection needed since every 128-bit
/// pattern is a valid GF(2^128) element).
#[cfg(feature = "prover")]
pub fn sample_ap(n: usize) -> Vec<Field2_128> {
    use rand::RngCore;
    let mut rng = rand::rng();
    let mut bytes = alloc::vec![0u8; n * FIELD2_128_BYTES];
    rng.fill_bytes(&mut bytes);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let chunk: &[u8] = &bytes[i * FIELD2_128_BYTES..(i + 1) * FIELD2_128_BYTES];
        let arr: [u8; FIELD2_128_BYTES] = chunk.try_into().expect("16-byte chunk");
        out.push(Field2_128::from_u128(u128::from_le_bytes(arr)));
    }
    out
}

/// Compute the MAC pair for a single 32-byte message.
///
/// `msg_le` MUST be the LE-byte form of the bound value (matches the
/// C++ `MACReference::compute` convention and the in-circuit `MAC::v128`
/// view). Returns `[mac0, mac1]` where:
///   * `m_i = of_bytes_field(&msg_le[i*16 .. (i+1)*16])`
///   * `mac_i = (av + ap[i]) * m_i`
///
/// Mirrors C++ `MACReference::compute` (mac_reference.h:43-51).
pub fn compute_mac(av: &Field2_128, ap: &[Field2_128; 2], msg_le: &[u8; MAC_MESSAGE_BYTES])
    -> [Field2_128; 2]
{
    let mut out = [Field2_128::ZERO; 2];
    for i in 0..MAC_VALUES_PER_MESSAGE {
        let mut chunk = [0u8; FIELD2_128_BYTES];
        chunk.copy_from_slice(&msg_le[i * FIELD2_128_BYTES..(i + 1) * FIELD2_128_BYTES]);
        let m = Field2_128::from_u128(u128::from_le_bytes(chunk));
        out[i] = (*av + ap[i]) * m;
    }
    out
}

/// Compute MACs for all 4 p7s-bound messages from their LE-byte forms.
/// Returns `[mac for msg_e (2), mac for msg_e2 (2), mac for spki_x (2),
/// mac for spki_y (2)]` — flat 8-element array, matching the C++
/// `kMacMsgIdx*` slicing convention used by `update_macs` and the
/// dense-array filler.
pub fn compute_all_macs(
    av: &Field2_128,
    ap: &[Field2_128; TOTAL_MAC_VALUES],
    msg_e_le: &[u8; MAC_MESSAGE_BYTES],
    msg_e2_le: &[u8; MAC_MESSAGE_BYTES],
    msg_spki_x_le: &[u8; MAC_MESSAGE_BYTES],
    msg_spki_y_le: &[u8; MAC_MESSAGE_BYTES],
) -> [Field2_128; TOTAL_MAC_VALUES] {
    let mut out = [Field2_128::ZERO; TOTAL_MAC_VALUES];
    let messages = [msg_e_le, msg_e2_le, msg_spki_x_le, msg_spki_y_le];
    let indices = [MAC_MSG_IDX_E, MAC_MSG_IDX_E2, MAC_MSG_IDX_SPKI_X, MAC_MSG_IDX_SPKI_Y];
    for (msg_idx, msg) in indices.iter().zip(messages.iter()) {
        let base = msg_idx * MAC_VALUES_PER_MESSAGE;
        let ap_pair: [Field2_128; 2] = [ap[base], ap[base + 1]];
        let macs = compute_mac(av, &ap_pair, msg);
        out[base] = macs[0];
        out[base + 1] = macs[1];
    }
    out
}

/// Serialize a `Field2_128` element to 16 little-endian bytes.
/// Inverse of `from_le_bytes`; matches C++ `gf_.to_bytes` for the
/// GF(2^128) field. Used for proof-bytes serialization (the proof
/// blob carries 8 mac values × 16 bytes = 128 bytes after the schema
/// version u32).
pub fn field_to_le_bytes(elt: &Field2_128) -> [u8; FIELD2_128_BYTES] {
    let mut bytes = [0u8; FIELD2_128_BYTES];
    let mut cursor = crate::io::Cursor::new(&mut bytes[..]);
    crate::Codec::encode(elt, &mut cursor).expect("Field2_128 encode to fixed buffer");
    bytes
}

/// Deserialize a `Field2_128` element from 16 little-endian bytes.
/// Mirrors C++ `gf_.of_bytes_field` — every 16-byte pattern is a valid
/// GF(2^128) element, so this never fails (returns `None` only on
/// length mismatch upstream).
pub fn field_from_le_bytes(bytes: &[u8; FIELD2_128_BYTES]) -> Field2_128 {
    Field2_128::from_u128(u128::from_le_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAC algebraic identity: with all-zero `ap`, `mac[i] = av * msg_half_i`.
    /// Verifies the algebraic relation matches `MACReference::compute` exactly.
    #[test]
    fn compute_mac_with_zero_ap_is_av_times_msg() {
        let av = Field2_128::from_u128(
            0x0123456789abcdef_u128 << 64 | 0xfedcba9876543210_u128,
        );
        let ap = [Field2_128::ZERO, Field2_128::ZERO];
        // 32-byte message: low half = 0x01 || 0x00..., high half = 0x02 || 0x00...
        let mut msg = [0u8; MAC_MESSAGE_BYTES];
        msg[0] = 0x01;
        msg[16] = 0x02;
        let macs = compute_mac(&av, &ap, &msg);
        assert_eq!(macs[0], av * Field2_128::from_u128(0x01));
        assert_eq!(macs[1], av * Field2_128::from_u128(0x02));
    }

    /// `(av + 0) * 0 == 0` regardless of av.
    #[test]
    fn compute_mac_with_zero_msg_is_zero() {
        let av = Field2_128::from_u128(0xdeadbeefcafebabe);
        let ap = [Field2_128::from_u128(7), Field2_128::from_u128(11)];
        let msg = [0u8; MAC_MESSAGE_BYTES];
        let macs = compute_mac(&av, &ap, &msg);
        assert_eq!(macs[0], Field2_128::ZERO);
        assert_eq!(macs[1], Field2_128::ZERO);
    }

    /// Each call to `compute_mac` is deterministic given inputs.
    #[test]
    fn compute_mac_is_deterministic() {
        let av = Field2_128::from_u128(42);
        let ap = [Field2_128::from_u128(13), Field2_128::from_u128(17)];
        let msg = [0xAA; MAC_MESSAGE_BYTES];
        let a = compute_mac(&av, &ap, &msg);
        let b = compute_mac(&av, &ap, &msg);
        assert_eq!(a, b);
    }

    /// The `compute_all_macs` flat-array convention writes each
    /// message's pair at `[msg_idx*2 .. (msg_idx+1)*2]`. Validate the
    /// slot ordering by inspecting individual slots.
    #[test]
    fn compute_all_macs_slot_ordering() {
        let av = Field2_128::from_u128(1);
        let ap = [Field2_128::ZERO; TOTAL_MAC_VALUES];
        // Distinct messages so each pair gets a distinct mac value.
        let mut msg_e = [0u8; MAC_MESSAGE_BYTES];
        msg_e[0] = 0x01;
        let mut msg_e2 = [0u8; MAC_MESSAGE_BYTES];
        msg_e2[0] = 0x02;
        let mut msg_x = [0u8; MAC_MESSAGE_BYTES];
        msg_x[0] = 0x03;
        let mut msg_y = [0u8; MAC_MESSAGE_BYTES];
        msg_y[0] = 0x04;

        let macs = compute_all_macs(&av, &ap, &msg_e, &msg_e2, &msg_x, &msg_y);

        // av + 0 = av = ONE; ONE * msg_low_value = msg_low_value.
        assert_eq!(macs[MAC_MSG_IDX_E * MAC_VALUES_PER_MESSAGE], Field2_128::from_u128(0x01));
        assert_eq!(macs[MAC_MSG_IDX_E2 * MAC_VALUES_PER_MESSAGE], Field2_128::from_u128(0x02));
        assert_eq!(macs[MAC_MSG_IDX_SPKI_X * MAC_VALUES_PER_MESSAGE], Field2_128::from_u128(0x03));
        assert_eq!(macs[MAC_MSG_IDX_SPKI_Y * MAC_VALUES_PER_MESSAGE], Field2_128::from_u128(0x04));
    }

    /// Round-trip: encode → decode is the identity.
    #[test]
    fn field_le_bytes_round_trip() {
        let v = Field2_128::from_u128(0x0123456789abcdef_u128 << 64 | 0xfedcba9876543210);
        let bytes = field_to_le_bytes(&v);
        let v2 = field_from_le_bytes(&bytes);
        assert_eq!(v, v2);
    }

    /// `field_to_le_bytes(ZERO)` is 16 zero bytes; `field_from_le_bytes`
    /// of the all-zero buffer is ZERO. Pinning the encoding so it can't
    /// silently drift to BE without a test catching it.
    #[test]
    fn field_le_bytes_zero_encoding() {
        let zero_bytes = field_to_le_bytes(&Field2_128::ZERO);
        assert_eq!(zero_bytes, [0u8; FIELD2_128_BYTES]);
        assert_eq!(field_from_le_bytes(&zero_bytes), Field2_128::ZERO);
    }

    /// Concrete LE encoding: 0x01_u128 must serialize as
    /// `01 00 00 ... 00`. Catches any swap to BE.
    #[test]
    fn field_le_bytes_one_encoding() {
        let one_bytes = field_to_le_bytes(&Field2_128::from_u128(1));
        let mut expected = [0u8; FIELD2_128_BYTES];
        expected[0] = 0x01;
        assert_eq!(one_bytes, expected);
    }

    #[cfg(feature = "prover")]
    #[test]
    fn sample_ap_returns_n_distinct_elements() {
        let ap = sample_ap(8);
        assert_eq!(ap.len(), 8);
        // Vanishingly unlikely that any two of 8 random GF(2^128)
        // values collide; using this as a basic sanity that the RNG is
        // wired in (not all-zeros).
        let mut nonzero_count = 0usize;
        for x in &ap {
            if *x != Field2_128::ZERO {
                nonzero_count += 1;
            }
        }
        assert!(nonzero_count >= 7, "RNG appears to produce zero values");
    }
}
