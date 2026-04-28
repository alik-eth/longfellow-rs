//! Sig-side per-message MacWitness.
//!
//! Mirrors C++ `MacWitness<Fp256Base>` at
//! `vendor/longfellow-zk/lib/circuits/mac/mac_witness.h:27-69` plus the four
//! call sites in `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:2627-2646`.
//!
//! Per message (e, e2, spki_x, spki_y), pushes 256 `FieldP256` wires into
//! the sig-circuit dense filler:
//!   * 2 × 64 elements packing the two 128-bit `ap` halves (LSB-first 2
//!     bits per element)
//!   * 2 × 64 elements packing the two 128-bit halves of the LE-byte message
//!     (same packing)
//!
//! Total per message = 256 wires; over 4 messages = 1024 wires. Combined with
//! the 9 native MAC values (8 macs + 1 av) at the public-input boundary,
//! this is the entire MAC contribution to the sig circuit.

use crate::{
    fields::{FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    mdoc_zk::bit_plucker::BitPlucker,
    p7s_zk::mac::{FIELD2_128_BYTES, MAC_MESSAGE_BYTES, MAC_VALUES_PER_MESSAGE},
};
use alloc::vec::Vec;

/// Bits per `Field2_128` (gf2k) element.
const F128_BITS: usize = 128;

/// Plucker bit-width — matches C++ `BitPluckerEncoder<Field, 2>`.
const PLUCKER_BITS: usize = 2;

/// Element count per packed 128-bit value with PLUCKER_BITS=2: ceil(128/2) = 64.
const PACK_PER_V128: usize = (F128_BITS + PLUCKER_BITS - 1) / PLUCKER_BITS;

/// Push the bits of a `Field2_128` element LSB-first, 2 at a time, packing
/// into 64 `FieldP256` elements.
///
/// Mirrors C++ `BitPluckerEncoder<Field, 2>::pack<packed_v128>(tmp, 128)`
/// where `tmp[j] = element[j]` for `j ∈ [0..128)`.
fn push_packed_v128(out: &mut Vec<FieldP256>, plucker: &BitPlucker<2, FieldP256>, value: Field2_128) {
    let bits: [bool; F128_BITS] = {
        let mut bits = [false; F128_BITS];
        for (i, b) in value.iter_bits().take(F128_BITS).enumerate() {
            bits[i] = b;
        }
        bits
    };
    for chunk_start in (0..F128_BITS).step_by(PLUCKER_BITS) {
        // Pack `PLUCKER_BITS` bits LSB-first into a small integer 0..(1 << PLUCKER_BITS).
        let mut v: u16 = 0;
        for j in 0..PLUCKER_BITS {
            if bits[chunk_start + j] {
                v |= 1u16 << j;
            }
        }
        out.push(plucker.encode(v));
    }
    debug_assert!(out.len() % PACK_PER_V128 == 0 || out.len() >= PACK_PER_V128);
}

/// Push the bits of a 16-byte LE byte buffer LSB-first, 2 at a time, packing
/// into 64 `FieldP256` elements.
///
/// Equivalent to converting the 16 bytes to a `Field2_128` via `from_u128(le)`
/// and calling [`push_packed_v128`], but without the round-trip — used for
/// the message halves where we want to honor C++ `gf_.of_bytes_field(...)`'s
/// LE-byte interpretation directly.
fn push_packed_v128_le_bytes(
    out: &mut Vec<FieldP256>,
    plucker: &BitPlucker<2, FieldP256>,
    le_half: &[u8; FIELD2_128_BYTES],
) {
    let value = Field2_128::from_u128(u128::from_le_bytes(*le_half));
    push_packed_v128(out, plucker, value);
}

/// Drive a single per-message `MacWitness::fill_witness` for the sig circuit.
///
/// Push order:
///   1. ap[0] packed (64 elements)
///   2. ap[1] packed (64 elements)
///   3. msg low half packed (64 elements)
///   4. msg high half packed (64 elements)
///
/// Total: `MAC_VALUES_PER_MESSAGE * 2 * PACK_PER_V128 = 256` `FieldP256` elements.
///
/// `ap_pair` MUST be the pair of `Field2_128` shares for THIS message
/// (`ap[msg_idx*2]` and `ap[msg_idx*2 + 1]`).
///
/// `msg_le` MUST be the 32-byte LE form of the message (e/e2/spki_x/spki_y).
///
/// Mirror of C++ `MacWitness<Fp256Base>::fill_witness` at
/// `mac_witness.h:38-54`.
pub(crate) fn push_mac_witness(
    out: &mut Vec<FieldP256>,
    ap_pair: &[Field2_128; MAC_VALUES_PER_MESSAGE],
    msg_le: &[u8; MAC_MESSAGE_BYTES],
) {
    let plucker = BitPlucker::<2, FieldP256>::new();
    for ap_half in ap_pair.iter() {
        push_packed_v128(out, &plucker, *ap_half);
    }
    for half_idx in 0..MAC_VALUES_PER_MESSAGE {
        let mut le_half = [0u8; FIELD2_128_BYTES];
        le_half.copy_from_slice(
            &msg_le[half_idx * FIELD2_128_BYTES..(half_idx + 1) * FIELD2_128_BYTES],
        );
        push_packed_v128_le_bytes(out, &plucker, &le_half);
    }
}

/// Number of `FieldP256` wires pushed per `push_mac_witness` call.
pub(crate) const MAC_WITNESS_WIRES_PER_MESSAGE: usize =
    MAC_VALUES_PER_MESSAGE * 2 * PACK_PER_V128;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p7s_zk::mac::MAC_MESSAGES_COUNT;

    #[test]
    fn push_mac_witness_pushes_256_wires() {
        let ap = [Field2_128::ZERO, Field2_128::ZERO];
        let msg = [0u8; MAC_MESSAGE_BYTES];
        let mut out = Vec::new();
        push_mac_witness(&mut out, &ap, &msg);
        assert_eq!(out.len(), MAC_WITNESS_WIRES_PER_MESSAGE);
        assert_eq!(out.len(), 256);
    }

    #[test]
    fn four_messages_total_1024_wires() {
        let ap_pair = [Field2_128::ZERO, Field2_128::ZERO];
        let msg = [0u8; MAC_MESSAGE_BYTES];
        let mut out = Vec::new();
        for _ in 0..MAC_MESSAGES_COUNT {
            push_mac_witness(&mut out, &ap_pair, &msg);
        }
        assert_eq!(out.len(), MAC_MESSAGES_COUNT * MAC_WITNESS_WIRES_PER_MESSAGE);
        assert_eq!(out.len(), 1024);
    }

    #[test]
    fn zero_ap_zero_msg_packs_to_repeated_encode_zero() {
        let ap = [Field2_128::ZERO, Field2_128::ZERO];
        let msg = [0u8; MAC_MESSAGE_BYTES];
        let mut out = Vec::new();
        push_mac_witness(&mut out, &ap, &msg);
        let plucker = BitPlucker::<2, FieldP256>::new();
        let zero_encoded = plucker.encode(0);
        for w in out {
            assert_eq!(w, zero_encoded);
        }
    }

    #[test]
    fn ap_low_bit_one_pack_pattern() {
        // ap[0] = 1 (only bit 0 set). After packing 2-bit-LSB:
        // first element = encode(0b01); rest = encode(0).
        let ap = [Field2_128::ONE, Field2_128::ZERO];
        let msg = [0u8; MAC_MESSAGE_BYTES];
        let mut out = Vec::new();
        push_mac_witness(&mut out, &ap, &msg);
        let plucker = BitPlucker::<2, FieldP256>::new();
        let one_encoded = plucker.encode(1);
        let zero_encoded = plucker.encode(0);
        assert_eq!(out[0], one_encoded);
        for w in &out[1..PACK_PER_V128] {
            assert_eq!(*w, zero_encoded);
        }
        // ap[1] = 0 → all 64 elements are encode(0).
        for w in &out[PACK_PER_V128..2 * PACK_PER_V128] {
            assert_eq!(*w, zero_encoded);
        }
    }

    #[test]
    fn msg_low_byte_one_pack_pattern() {
        // msg_le[0] = 1 → low half u128 = 1; high half u128 = 0.
        let ap = [Field2_128::ZERO, Field2_128::ZERO];
        let mut msg = [0u8; MAC_MESSAGE_BYTES];
        msg[0] = 1;
        let mut out = Vec::new();
        push_mac_witness(&mut out, &ap, &msg);
        let plucker = BitPlucker::<2, FieldP256>::new();
        let one_encoded = plucker.encode(1);
        let zero_encoded = plucker.encode(0);
        // ap region (first 128 elements) is all zero.
        for w in &out[..2 * PACK_PER_V128] {
            assert_eq!(*w, zero_encoded);
        }
        // msg low half: first packed element encodes bit 0 = 1, rest encode 0.
        let msg_low_start = 2 * PACK_PER_V128;
        assert_eq!(out[msg_low_start], one_encoded);
        for w in &out[msg_low_start + 1..msg_low_start + PACK_PER_V128] {
            assert_eq!(*w, zero_encoded);
        }
        // msg high half: all encode(0).
        for w in &out[msg_low_start + PACK_PER_V128..] {
            assert_eq!(*w, zero_encoded);
        }
    }
}
