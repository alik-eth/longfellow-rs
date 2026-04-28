//! Hash + sig witness vector orchestrators.
//!
//! Mirrors C++ `prove(...)` at `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:2440-2653`.
//!
//! The hash-side vector consists of:
//!   1. Public-input region (1842 wires, filled via existing `fill_hash_*` helpers)
//!   2. Private region — driven append-style in fill order matching the C++
//!      `DenseFiller<Field2_128>::push_back` sequence.
//!
//! The sig-side vector consists of:
//!   1. Public-input region (1154 wires, filled via existing `fill_sig_*` helpers)
//!   2. Private region — Holder-pk + e/e2 + 4 MacWitness fills + 2 ECDSA witness fills.

use crate::{
    fields::{FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    p7s_zk::{
        invariants::{
            push_invariant4_witness, push_invariant5_witness, push_invariant6_witness,
            push_invariant10_witness, push_invariant13_witness,
        },
        layout::{
            CERT_TBS_MAX_BLOCKS, HASH_PUB_TOTAL, MESSAGE_DIGEST_LEN, SIGNED_ATTRS_MAX_BLOCKS,
            SIG_PUB_TOTAL, fill_hash_public_pre_mac, fill_sig_public_pre_mac,
            split_hash_statement, split_sig_statement,
        },
        mac::{MAC_MESSAGE_BYTES, MAC_VALUES_PER_MESSAGE, TOTAL_MAC_VALUES},
        mac_witness::push_mac_witness,
        preimages::{
            build_enroll_commit_sha_witness, build_enroll_nullifier_sha_witness,
            build_nullifier_sha_witness, ENROLL_COMMIT_SHA_BLOCKS,
            ENROLL_NULLIFIER_SHA_BLOCKS, NULLIFIER_SHA_BLOCKS,
        },
        public_inputs::ParsedPublic,
        sha256_witness::{
            ShaWitness, compute_sha_witness, push_sha_block_witnesses, push_sha_padded_bytes,
            push_uint, push_v8,
        },
        witness::ParsedWitness,
    },
};
use alloc::vec::Vec;

/// Off-circuit SHA padding constants for the JSON-bound regions.
///
/// C++: `kContextMaxBlocks = 1`, `kSignedContentMaxBlocks = 16`
/// (`vendor/longfellow-zk/lib/circuits/p7s/p7s_hash.h:36,46`).
pub(crate) const CONTEXT_MAX_BLOCKS: usize = 1;
pub(crate) const SIGNED_CONTENT_MAX_BLOCKS: usize = 16;

/// Bit width of cert_tbs / signed_attrs offset wires.
///
/// C++: `kCertTbsLenBits = kSignedAttrsLenBits = 11`
/// (`p7s_circuit.h:49,69`).
const CERT_TBS_LEN_BITS: usize = 11;
const SIGNED_ATTRS_LEN_BITS: usize = 11;

/// SPKI byte-window offset constants. The SPKI prefix is 26 bytes; the
/// uncompressed-EC point starts at +26 (the `04` SEC1 tag), with X at +27
/// and Y at +27+32 = +59 from the absolute SPKI offset.
///
/// C++: `kSpkiPrefixLen = 26`, `kSpkiXYLen = 32`.
pub(crate) const SPKI_PREFIX_LEN: usize = 26;
pub(crate) const SPKI_XY_LEN: usize = 32;

/// Off-circuit SHA witnesses computed during hash-side fill, retained for
/// reuse by the sig side (avoids recomputing `e`/`e2` digests).
pub(crate) struct HashSideShaWitnesses {
    pub(crate) cert_sw: ShaWitness,
    /// SHA-256(cert_tbs[..cert_tbs_len]) in big-endian byte order.
    pub(crate) e_digest_be: [u8; 32],
    /// SHA-256(signed_attrs_canonical[..signed_attrs_len]) in big-endian byte order.
    pub(crate) e2_digest_be: [u8; 32],
}

/// Build the canonical-form `signed_attrs` buffer. The witness blob's first
/// byte is `0xA0` (CAdES `[0] IMPLICIT`); for SHA-256 input the first byte is
/// rewritten to `0x31` (SET OF) and the rest is unchanged.
///
/// C++: `p7s_zk.cc:2347-2354` (the canonical-form rewrite).
fn signed_attrs_canonical(wit: &ParsedWitness) -> Vec<u8> {
    let mut canonical = wit.signed_attrs.clone();
    if !canonical.is_empty() {
        canonical[0] = 0x31;
    }
    canonical
}

/// Append the entire hash-side private region to `out` in the order required
/// by `build_hash_circuit()`'s `vinput<W>` declarations.
///
/// On entry, `out` MUST be the public-input region only (length `HASH_PUB_TOTAL`,
/// MAC region zero-initialized as placeholders). On return, `out` has length
/// equal to the hash circuit's `ninputs`.
///
/// `ap` is the prover's committed mac shares — exactly `TOTAL_MAC_VALUES` (8)
/// elements. They are appended as the last private push (one EltW each).
///
/// Returns the SHA witnesses needed for the sig side (cert_tbs SHA, e/e2
/// digests).
///
/// C++: `p7s_zk.cc:2440-2582`.
pub(crate) fn append_hash_private_region(
    out: &mut Vec<Field2_128>,
    wit: &ParsedWitness,
    pub_: &ParsedPublic,
    ap: &[Field2_128; TOTAL_MAC_VALUES],
) -> HashSideShaWitnesses {
    debug_assert_eq!(
        out.len(),
        HASH_PUB_TOTAL,
        "append_hash_private_region: input must be public-input region only"
    );

    // Step 3 — holder_seed[32] (FIRST private push).
    for &b in &wit.holder_seed {
        push_v8(out, b);
    }

    // Step 4-6 — context SHA witness.
    let context_real = &wit.context[..wit.context_len as usize];
    let ctx_sw = compute_sha_witness(context_real, CONTEXT_MAX_BLOCKS);
    push_v8(out, ctx_sw.numb);
    push_sha_padded_bytes(out, &ctx_sw);
    push_sha_block_witnesses(out, &ctx_sw);

    // Step 7 — signed_content SHA-padded bytes (block witnesses pushed later
    // at step 14 — order required by the in-circuit declaration).
    let sc_real = &wit.signed_content[..wit.signed_content_len as usize];
    let sc_sw = compute_sha_witness(sc_real, SIGNED_CONTENT_MAX_BLOCKS);
    push_sha_padded_bytes(out, &sc_sw);

    // Step 8-12 — invariants 4/5/6/10/13.
    push_invariant4_witness(out, wit.json_pk_offset, &wit.pk_hex);
    push_invariant5_witness(out, wit.json_nonce_offset, &wit.nonce_hex);
    push_invariant6_witness(out, wit.json_context_offset);
    push_invariant10_witness(out, wit.json_declaration_offset);
    push_invariant13_witness(
        out,
        wit.json_holder_seed_commit_offset,
        &wit.holder_seed_commit_hex,
    );

    // Step 13 — sc.numb v8.
    push_v8(out, sc_sw.numb);

    // Step 14 — signed_content per-block SHA witnesses.
    push_sha_block_witnesses(out, &sc_sw);

    // Step 15 — message_digest[32].
    debug_assert_eq!(wit.message_digest.len(), MESSAGE_DIGEST_LEN);
    for &b in &wit.message_digest {
        push_v8(out, b);
    }

    // Step 16-19 — cert_tbs SHA witness + e_digest.
    let cert_real = &wit.cert_tbs[..wit.cert_tbs_len as usize];
    let cert_sw = compute_sha_witness(cert_real, CERT_TBS_MAX_BLOCKS);
    push_v8(out, cert_sw.numb);
    push_uint(out, u64::from(wit.cert_tbs_spki_offset), CERT_TBS_LEN_BITS);
    push_sha_padded_bytes(out, &cert_sw);
    push_sha_block_witnesses(out, &cert_sw);

    // e_digest_be — claimed SHA-256(cert_tbs) in BE.
    let e_digest_be = cert_sw.digest;
    for &b in &e_digest_be {
        push_v8(out, b);
    }

    // Step 21-25 — signedAttrs SHA witness + e2_digest.
    let sa_canonical = signed_attrs_canonical(wit);
    let sa_real = &sa_canonical[..wit.signed_attrs_len as usize];
    let sa_sw = compute_sha_witness(sa_real, SIGNED_ATTRS_MAX_BLOCKS);
    push_v8(out, sa_sw.numb);
    push_uint(
        out,
        u64::from(wit.signed_attrs_md_offset),
        SIGNED_ATTRS_LEN_BITS,
    );
    push_sha_padded_bytes(out, &sa_sw);
    push_sha_block_witnesses(out, &sa_sw);

    let e2_digest_be = sa_sw.digest;
    for &b in &e2_digest_be {
        push_v8(out, b);
    }

    // Step 26-27 — subject_sn / subject_dn offsets in cert_tbs (v11 each).
    push_uint(
        out,
        u64::from(wit.subject_sn_offset_in_tbs),
        CERT_TBS_LEN_BITS,
    );
    push_uint(
        out,
        u64::from(wit.subject_dn_start_offset_in_tbs),
        CERT_TBS_LEN_BITS,
    );

    // Step 28-30 — nullifier SHA witness.
    let null_sw = build_nullifier_sha_witness(&wit.holder_seed, &pub_.context_hash);
    debug_assert_eq!(null_sw.max_blocks, NULLIFIER_SHA_BLOCKS);
    push_v8(out, null_sw.numb);
    push_sha_padded_bytes(out, &null_sw);
    push_sha_block_witnesses(out, &null_sw);

    // Step 31-32 — enroll_commit SHA witness.
    let ec_sw = build_enroll_commit_sha_witness(&wit.holder_seed);
    debug_assert_eq!(ec_sw.max_blocks, ENROLL_COMMIT_SHA_BLOCKS);
    push_sha_padded_bytes(out, &ec_sw);
    push_sha_block_witnesses(out, &ec_sw);

    // Step 33-34 — enroll_nullifier SHA witness.
    let stable_id = crate::p7s_zk::preimages::extract_stable_id(
        &wit.cert_tbs,
        wit.subject_sn_offset_in_tbs as usize,
    )
    .expect("subject_sn_offset_in_tbs window fits in cert_tbs (parser-validated)");
    let en_sw = build_enroll_nullifier_sha_witness(&stable_id);
    debug_assert_eq!(en_sw.max_blocks, ENROLL_NULLIFIER_SHA_BLOCKS);
    push_sha_padded_bytes(out, &en_sw);
    push_sha_block_witnesses(out, &en_sw);

    // Step 35 — committed `ap` halves (TOTAL_MAC_VALUES = 8 native EltW).
    for &ap_value in ap.iter() {
        out.push(ap_value);
    }

    HashSideShaWitnesses {
        cert_sw,
        e_digest_be,
        e2_digest_be,
    }
}

/// Append the entire sig-side private region to `out` in the order required
/// by `build_sig_circuit()`.
///
/// On entry, `out` MUST be the public-input region only (length `SIG_PUB_TOTAL`,
/// MAC region zero-initialized as placeholders). On return, `out` has length
/// equal to the sig circuit's `ninputs`.
///
/// `holder_pk_x_be`, `holder_pk_y_be` — the 32 BE-byte X / Y coordinates of
/// the holder's P-256 pubkey, sourced from `cert_tbs[spki_x_abs..]`.
///
/// `e_digest_be`, `e2_digest_be` — the BE-byte SHA-256 digests carried over
/// from the hash side.
///
/// `cert_ecdsa_witness_wires`, `content_ecdsa_witness_wires` — pre-computed
/// per-circuit ECDSA witness wires (these come from
/// `mdoc_zk::ec::fill_ecdsa_witness` reach-through; see sub-PR 7).
///
/// C++: `p7s_zk.cc:2584-2653`.
pub(crate) fn append_sig_private_region(
    out: &mut Vec<FieldP256>,
    holder_pk_x_be: &[u8; SPKI_XY_LEN],
    holder_pk_y_be: &[u8; SPKI_XY_LEN],
    e_digest_be: &[u8; 32],
    e2_digest_be: &[u8; 32],
    spki_x_be: &[u8; SPKI_XY_LEN],
    spki_y_be: &[u8; SPKI_XY_LEN],
    ap: &[Field2_128; TOTAL_MAC_VALUES],
    cert_ecdsa_witness_wires: &[FieldP256],
    content_ecdsa_witness_wires: &[FieldP256],
) {
    debug_assert_eq!(
        out.len(),
        SIG_PUB_TOTAL,
        "append_sig_private_region: input must be public-input region only"
    );

    // Step 4-5 — holder_pkX, holder_pkY (Montgomery form, but FieldP256
    // internal repr is already Montgomery — `try_from_be` from the BE 32 bytes
    // of the SPKI window does the right thing).
    let holder_pk_x = field_p256_from_be_bytes(holder_pk_x_be).expect("holder pk X parses");
    let holder_pk_y = field_p256_from_be_bytes(holder_pk_y_be).expect("holder pk Y parses");
    out.push(holder_pk_x);
    out.push(holder_pk_y);

    // Step 6-7 — e_elt, e2_elt (cert_tbs/signedAttrs digests as base-field elts).
    let e_elt = field_p256_from_be_bytes(e_digest_be).expect("e digest fits in field");
    let e2_elt = field_p256_from_be_bytes(e2_digest_be).expect("e2 digest fits in field");
    out.push(e_elt);
    out.push(e2_elt);

    // Step 8 — 4 MacWitness fills (e, e2, spki_x, spki_y).
    let e_le = reverse_to_le(e_digest_be);
    let e2_le = reverse_to_le(e2_digest_be);
    let spki_x_le = reverse_to_le(spki_x_be);
    let spki_y_le = reverse_to_le(spki_y_be);

    let messages: [(&[u8; MAC_MESSAGE_BYTES], usize); 4] = [
        (&e_le, 0),
        (&e2_le, 1),
        (&spki_x_le, 2),
        (&spki_y_le, 3),
    ];
    for (msg_le, msg_idx) in messages.iter() {
        let base = msg_idx * MAC_VALUES_PER_MESSAGE;
        let ap_pair = [ap[base], ap[base + 1]];
        push_mac_witness(out, &ap_pair, msg_le);
    }

    // Step 9-10 — cert ECDSA witness, content ECDSA witness.
    out.extend_from_slice(cert_ecdsa_witness_wires);
    out.extend_from_slice(content_ecdsa_witness_wires);
}

/// Reverse a 32-byte BE buffer into a 32-byte LE buffer.
///
/// Used for MAC binding which requires LE-byte form per
/// C++ `p7s_zk.cc:2613-2624`.
fn reverse_to_le(be: &[u8; MAC_MESSAGE_BYTES]) -> [u8; MAC_MESSAGE_BYTES] {
    let mut le = [0u8; MAC_MESSAGE_BYTES];
    for i in 0..MAC_MESSAGE_BYTES {
        le[i] = be[MAC_MESSAGE_BYTES - 1 - i];
    }
    le
}

/// Decode a 32-byte BE buffer to a `FieldP256` element (Montgomery domain
/// internally). Mirrors C++ `p256_base.to_montgomery(nat_from_be(be))`.
fn field_p256_from_be_bytes(be: &[u8; 32]) -> Option<FieldP256> {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    FieldP256::try_from(&le).ok()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_to_le_swaps_endianness() {
        let mut be = [0u8; MAC_MESSAGE_BYTES];
        for i in 0..MAC_MESSAGE_BYTES {
            be[i] = i as u8;
        }
        let le = reverse_to_le(&be);
        for i in 0..MAC_MESSAGE_BYTES {
            assert_eq!(le[i], (MAC_MESSAGE_BYTES - 1 - i) as u8);
        }
    }
}
