//! Compile-time bounds and length constants mirroring
//! `vendor/longfellow-zk/lib/circuits/p7s/p7s_circuit.h` and
//! `p7s_hash.h`. These are the dimensions the C++ side baked into the
//! pre-compiled p7s circuit binary; the Rust consumer must agree byte-
//! for-byte on every blob field, public-input wire count, and SHA
//! block-count for `verify(public_blob, proof)` to round-trip against
//! a C++-generated proof.
//!
//! Any change here must be matched in both the C++ source and the
//! pre-compiled circuit. Treat as a frozen ABI surface.

/// Wire-format schema version baked into both blobs. v13 (Task #37)
/// is the variable-length-serialNumber schema; the wire layout is
/// byte-identical to v12 (holder-bound nullifier, 2026-04-28) — only
/// this version u32 distinguishes them, so v12 and v13 blobs are
/// mutually rejected at the parser version gate.
pub const BLOB_SCHEMA_VERSION: u32 = 13;

// ---- signed_content / context bounds ----

/// Maximum `signed_content` byte length (raw, before SHA padding).
pub const MAX_SIGNED_CONTENT: usize = 1024;

/// Maximum `context_bytes` byte length (raw). 32 bytes spans the
/// freshness-context window declared in the binding JSON.
pub const CONTEXT_MAX_BYTES: usize = 32;

// ---- hex-encoded JSON fields ----

/// Length of an uncompressed SEC1 P-256 public key as lowercase hex
/// (`04 || X[32] || Y[32]` = 65 bytes × 2 hex chars).
pub const PK_HEX_LEN: usize = 130;
/// Decoded P-256 public key length in bytes (uncompressed SEC1).
pub const PK_BYTES: usize = 65;

/// Decoded freshness nonce length in bytes.
pub const NONCE_BYTES: usize = 32;
/// Nonce serialized as lowercase hex (2 chars per byte).
pub const NONCE_HEX_LEN: usize = 64;

/// `holder_seed_commit` JSON field is a 32-byte SHA-256 digest
/// serialized as 64 lowercase hex characters in the binding JSON.
pub const HOLDER_SEED_COMMIT_HEX_LEN: usize = 64;
/// Decoded `holder_seed_commit` length in bytes.
pub const HOLDER_SEED_COMMIT_BYTES: usize = 32;

// ---- SHA-256 / digest bounds ----

/// Length of `blob.message_digest` (= SHA-256 of `signed_content`).
pub const MESSAGE_DIGEST_LEN: usize = 32;

// ---- cert_tbs (invariant 1 — signer-cert ECDSA) ----

/// `cert_tbs` SHA-256 block count. 32 blocks × 64 bytes = 2048-byte
/// padded buffer.
pub const CERT_TBS_MAX_BLOCKS: usize = 32;
/// `cert_tbs` padded byte length.
pub const CERT_TBS_MAX_BYTES: usize = CERT_TBS_MAX_BLOCKS * 64;

// ---- signedAttrs (invariant 2a — content ECDSA) ----

/// `signedAttrs` SHA-256 block count. 24 blocks × 64 bytes = 1536-byte
/// padded buffer.
pub const SIGNED_ATTRS_MAX_BLOCKS: usize = 24;
/// `signedAttrs` padded byte length.
pub const SIGNED_ATTRS_MAX_BYTES: usize = SIGNED_ATTRS_MAX_BLOCKS * 64;

// ---- SPKI binding (invariant 4 helper) ----

/// 26-byte fixed DER prefix of a P-256 `id-ecPublicKey` SubjectPublicKeyInfo.
pub const SPKI_PREFIX_LEN: usize = 26;
/// SPKI window: prefix + 0x04 SEC1 tag + X[32] + Y[32] = 91 bytes.
pub const SPKI_WINDOW_LEN: usize = SPKI_PREFIX_LEN + 1 + 64;

// ---- messageDigest binding (invariant 2c) ----

/// 17-byte CMS messageDigest attribute DER prefix.
pub const SIGNED_ATTRS_MD_PREFIX_LEN: usize = 17;
/// Anchor + digest = 17 + 32 = 49 bytes.
pub const SIGNED_ATTRS_MD_WINDOW_LEN: usize =
    SIGNED_ATTRS_MD_PREFIX_LEN + MESSAGE_DIGEST_LEN;

// ---- stable_id (invariant 7 helper) ----

/// Legacy DIIA RNOKPP stable-ID length (`TINUA-` + 10 digits = 16).
/// Retained as the canonical UA regression length; v13 (Task #37)
/// accepts any length in `[STABLE_ID_MIN_LEN, STABLE_ID_MAX_LEN]`.
pub const STABLE_ID_LEN: usize = 16;
/// v13 (Task #37) — minimum stable-ID value length. Mirrors the
/// circuit `kStableIdMinLen`.
pub const STABLE_ID_MIN_LEN: usize = 8;
/// v13 (Task #37) — maximum stable-ID value length; keeps the
/// enroll_nullifier SHA-256 preimage (`1 + L + 16`) within a single
/// block. Mirrors the circuit `kStableIdMaxLen`.
pub const STABLE_ID_MAX_LEN: usize = 37;
/// 9-byte X.520 serialNumber attribute DER prefix.
pub const SUBJECT_SN_ANCHOR_LEN: usize = 9;
/// Routed serialNumber window: anchor + max value = 9 + 37 = 46 bytes.
/// The circuit routes the window at the max size regardless of the
/// actual value length `L`, which lives in anchor byte 8.
pub const SUBJECT_SN_WINDOW_LEN: usize = SUBJECT_SN_ANCHOR_LEN + STABLE_ID_MAX_LEN;

// ---- v12 nullifier / enroll outputs ----

/// `nullifier` public output length (SHA-256).
pub const NULLIFIER_LEN: usize = 32;
/// `enroll_commit` public output length (SHA-256).
pub const ENROLL_COMMIT_LEN: usize = 32;
/// `enroll_nullifier` public output length (SHA-256).
pub const ENROLL_NULLIFIER_LEN: usize = 32;

// ---- v12 holder secret ----

/// Private holder secret. 32 bytes. Path A derives from
/// deterministic-ECDSA wallet signature; Path B from TEE-ECDH.
pub const HOLDER_SEED_LEN: usize = 32;

// ---- declaration whitelist ----

/// Compile-time declaration phrase length asserted in-circuit.
pub const DECLARATION_LEN: usize = 510;

// ---- trust anchor table ----

/// Compile-time trust-anchor table size mirrored from the pre-compiled
/// circuit. Bound-checked in-circuit via `vlt(trust_anchor_index,
/// TRUST_ANCHOR_COUNT)`. Currently 2: TestAnchorA + TestAnchorB.
pub const TRUST_ANCHOR_COUNT: u32 = 2;

// ---- (r, s) raw scalar bytes ----

/// Big-endian raw scalar bytes for ECDSA signatures (DER-parsed in the
/// host before reaching the blob).
pub const ECDSA_SCALAR_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Public-input wire-layout constants (mirror C++ `kHashPub*` / `kSigPub*`
// in vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:470-562).
//
// These wire counts are baked into the pre-compiled p7s circuit binary;
// any drift between Rust and C++ here will cause the Sumcheck/Ligero
// verifier to reject otherwise-valid proofs. Treat as a frozen ABI.
// ---------------------------------------------------------------------------

/// Number of public-input wires for `pk_bytes` on the HASH circuit
/// (65 bytes × 8 bits = 520 wires, LSB-first per byte). Mirrors C++
/// `kHashPubPk = kPkBytes * 8`.
pub const PK_PUB_BITS: usize = PK_BYTES * 8;

/// Number of public-input wires for `nonce_bytes` on the HASH circuit
/// (32 bytes × 8 bits = 256 wires, LSB-first per byte). Mirrors C++
/// `kHashPubNonce = kNonceBytes * 8`.
pub const NONCE_PUB_BITS: usize = NONCE_BYTES * 8;

/// Pre-MAC public-input wire count for the HASH circuit (1833).
/// Equal to: 1 (const) + 256 (context_hash) + 520 (pk) + 256 (nonce) +
/// 256 (nullifier) + 256 (enroll_commit) + 256 (enroll_nullifier) + 32
/// (trust_anchor_index). Mirrors C++ `kHashPubPreMac` and the
/// `static_assert(kHashPubPreMac == 1833)` (`p7s_zk.cc:487`).
pub const HASH_PUB_PRE_MAC: usize = 1
    + 256
    + PK_PUB_BITS
    + NONCE_PUB_BITS
    + 256
    + 256
    + 256
    + 32;

/// Number of MAC values bound across the hash + sig field split
/// (4 messages × 2 GF(2^128) halves/message = 8). Mirrors C++
/// `kTotalMacValues = kMacMessagesCount * kMacValuesPerMessage` from
/// `vendor/longfellow-zk/lib/circuits/p7s/sub/p7s_signature.h:98`.
pub const TOTAL_MAC_VALUES: usize = 8;

/// HASH-side MAC public-input wires: `kTotalMacValues` mac values + 1
/// `av` random challenge = 9 native EltW. Mirrors C++
/// `kHashMacInputWires = kTotalMacValues + 1`.
pub const HASH_MAC_INPUT_WIRES: usize = TOTAL_MAC_VALUES + 1;

/// Total HASH-circuit public inputs = pre-MAC + MAC region. Pinned at
/// 1842 by C++ `static_assert(kHashPubTotal == 1842)`.
pub const HASH_PUB_TOTAL: usize = HASH_PUB_PRE_MAC + HASH_MAC_INPUT_WIRES;

/// SIG-circuit const-1 wire count (auto-allocated wire 0).
pub const SIG_PUB_CONST: usize = 1;

/// SIG-circuit `trust_anchor_index` public-input wire count (1 EltW).
pub const SIG_PUB_TRUST_ANCHOR_IDX: usize = 1;

/// Per-MAC-value bit-decomposition width on the SIG circuit
/// (`Fp256Base` can't hold a 128-bit GF(2^128) element as one wire,
/// so each `v128` is bit-decomposed). Mirrors C++ `kSigMacBitsPerWire`.
pub const SIG_MAC_BITS_PER_WIRE: usize = 128;

/// SIG-side MAC public-input wires: `(kTotalMacValues + 1) × 128 = 1152`.
/// Mirrors C++ `kSigMacInputWires`.
pub const SIG_MAC_INPUT_WIRES: usize = (TOTAL_MAC_VALUES + 1) * SIG_MAC_BITS_PER_WIRE;

/// Total SIG-circuit public inputs. Pinned at 1154 by C++
/// `static_assert(kSigPubTotal == 1154)`.
pub const SIG_PUB_TOTAL: usize = SIG_PUB_CONST + SIG_PUB_TRUST_ANCHOR_IDX + SIG_MAC_INPUT_WIRES;

/// Wire index where the hash-circuit MAC region begins. Mirrors C++
/// `kHashMacIndex`.
pub const HASH_MAC_INDEX: usize = HASH_PUB_PRE_MAC;

/// Wire index where the sig-circuit MAC region begins. Mirrors C++
/// `kSigMacIndex`.
pub const SIG_MAC_INDEX: usize = SIG_PUB_CONST + SIG_PUB_TRUST_ANCHOR_IDX;

// ---------------------------------------------------------------------------
// Wire-layout split + public-input fill (mirrors C++
// `fill_hash_public_inputs` at p7s_zk.cc:2165 and the verifier-side
// sig fill at p7s_zk.cc:2799-2806).
//
// The mdoc analog is `mdoc_zk::layout::split_hash_statement` /
// `split_signature_statement`. Same idea: a typed view over a flat
// `&mut [F]` slice with named fields per wire region.
// ---------------------------------------------------------------------------

use crate::fields::{FieldElement, field2_128::Field2_128, fieldp256::FieldP256};

use super::public_inputs::ParsedPublic;

/// Hash-circuit public-input layout (Field2_128, kHashPubTotal = 1842 wires).
///
///   [0]                              = const 1 (`Fs.one()`)
///   [1 .. 1 + 256)                   = context_hash v256 (push_target order)
///   [257 .. 257 + 520)               = pk_bytes (65 × v8, LSB-first per byte)
///   [777 .. 777 + 256)               = nonce_bytes (32 × v8, LSB-first per byte)
///   [1033 .. 1033 + 256)             = nullifier (push_target order)
///   [1289 .. 1289 + 256)             = enroll_commit (push_target order)
///   [1545 .. 1545 + 256)             = enroll_nullifier (push_target order)
///   [1801 .. 1801 + 32)              = trust_anchor_index v32 (LSB-first u32)
///   [1833 .. 1833 + 8)               = mac values (8 native EltW)
///   [1841]                           = av (native EltW)
pub(crate) struct SplitHashStatement<'a> {
    pub implicit_one: &'a mut Field2_128,
    pub context_hash: &'a mut [Field2_128; 256],
    pub pk: &'a mut [Field2_128; PK_PUB_BITS],
    pub nonce: &'a mut [Field2_128; NONCE_PUB_BITS],
    pub nullifier: &'a mut [Field2_128; 256],
    pub enroll_commit: &'a mut [Field2_128; 256],
    pub enroll_nullifier: &'a mut [Field2_128; 256],
    pub trust_anchor_index: &'a mut [Field2_128; 32],
    /// 8 mac values + av, native EltW each (filled post-commit).
    pub mac_region: &'a mut [Field2_128; HASH_MAC_INPUT_WIRES],
}

/// Segment a hash-circuit public-input slice into its named regions.
///
/// # Panics
/// Panics if `slice.len() != HASH_PUB_TOTAL`.
pub(crate) fn split_hash_statement(slice: &mut [Field2_128]) -> SplitHashStatement<'_> {
    assert_eq!(
        slice.len(),
        HASH_PUB_TOTAL,
        "hash statement length must equal kHashPubTotal = {HASH_PUB_TOTAL}"
    );

    let (implicit_one, rest) = slice.split_first_mut().unwrap();
    let (context_hash, rest) = rest.split_at_mut(256);
    let (pk, rest) = rest.split_at_mut(PK_PUB_BITS);
    let (nonce, rest) = rest.split_at_mut(NONCE_PUB_BITS);
    let (nullifier, rest) = rest.split_at_mut(256);
    let (enroll_commit, rest) = rest.split_at_mut(256);
    let (enroll_nullifier, rest) = rest.split_at_mut(256);
    let (trust_anchor_index, rest) = rest.split_at_mut(32);
    let (mac_region, rest) = rest.split_at_mut(HASH_MAC_INPUT_WIRES);
    assert!(rest.is_empty());

    SplitHashStatement {
        implicit_one,
        context_hash: context_hash.try_into().unwrap(),
        pk: pk.try_into().unwrap(),
        nonce: nonce.try_into().unwrap(),
        nullifier: nullifier.try_into().unwrap(),
        enroll_commit: enroll_commit.try_into().unwrap(),
        enroll_nullifier: enroll_nullifier.try_into().unwrap(),
        trust_anchor_index: trust_anchor_index.try_into().unwrap(),
        mac_region: mac_region.try_into().unwrap(),
    }
}

/// Sig-circuit public-input layout (FieldP256, kSigPubTotal = 1154 wires).
///
///   [0]                              = const 1
///   [1]                              = trust_anchor_index (single EltW, of_scalar)
///   [2 .. 2 + 1152)                  = mac region: 9 × v128 = 1152 bit-wires (LSB-first)
pub(crate) struct SplitSigStatement<'a> {
    pub implicit_one: &'a mut FieldP256,
    pub trust_anchor_index: &'a mut FieldP256,
    pub mac_region: &'a mut [FieldP256; SIG_MAC_INPUT_WIRES],
}

/// Segment a sig-circuit public-input slice into its named regions.
///
/// # Panics
/// Panics if `slice.len() != SIG_PUB_TOTAL`.
pub(crate) fn split_sig_statement(slice: &mut [FieldP256]) -> SplitSigStatement<'_> {
    assert_eq!(
        slice.len(),
        SIG_PUB_TOTAL,
        "sig statement length must equal kSigPubTotal = {SIG_PUB_TOTAL}"
    );

    let (implicit_one, rest) = slice.split_first_mut().unwrap();
    let (trust_anchor_index, rest) = rest.split_first_mut().unwrap();
    let (mac_region, rest) = rest.split_at_mut(SIG_MAC_INPUT_WIRES);
    assert!(rest.is_empty());

    SplitSigStatement {
        implicit_one,
        trust_anchor_index,
        mac_region: mac_region.try_into().unwrap(),
    }
}

/// Fill the pre-MAC region of a hash-circuit public-input statement
/// from a parsed public blob. Mirrors C++ `fill_hash_public_inputs`
/// (`p7s_zk.cc:2165`).
///
/// The `mac_region` is left untouched — the prover writes placeholders
/// before `commit`, and overwrites with real MAC values + `av` after
/// the post-commit Fiat-Shamir step. The verifier writes the MAC
/// values directly via `push_hash_mac_values`.
pub(crate) fn fill_hash_public_pre_mac(view: &mut SplitHashStatement<'_>, pub_: &ParsedPublic) {
    *view.implicit_one = Field2_128::ONE;
    push_target_be(view.context_hash, &pub_.context_hash);
    push_bytes_lsb_first(view.pk, &pub_.pk);
    push_bytes_lsb_first(view.nonce, &pub_.nonce);
    push_target_be(view.nullifier, &pub_.nullifier);
    push_target_be(view.enroll_commit, &pub_.enroll_commit);
    push_target_be(view.enroll_nullifier, &pub_.enroll_nullifier);
    push_uint_lsb_first_u32(view.trust_anchor_index, pub_.trust_anchor_index);
}

/// Fill the const-1 + trust-anchor-index region of a sig-circuit
/// public-input statement. The MAC region is left untouched.
///
/// Mirrors the verifier-side fill at `p7s_zk.cc:2799-2806` and the
/// prover-side at `p7s_zk.cc:2592-2596`.
pub(crate) fn fill_sig_public_pre_mac(view: &mut SplitSigStatement<'_>, pub_: &ParsedPublic) {
    *view.implicit_one = FieldP256::ONE;
    *view.trust_anchor_index = FieldP256::from_u128(u128::from(pub_.trust_anchor_index));
}

/// Write the post-commit MAC values + `av` challenge into the HASH-circuit
/// public-input statement's MAC region. Each is a single native EltW
/// (Field2_128 is 128 bits wide; v128 IS an EltW here). Mirrors C++
/// `push_hash_mac_values` (p7s_zk.cc:2192).
///
/// Wire order:
///   `mac_region[0..TOTAL_MAC_VALUES]` = mac values in `kMacMsgIdx*` order
///   `mac_region[TOTAL_MAC_VALUES]`    = `av`
pub(crate) fn fill_hash_mac_region(
    view: &mut SplitHashStatement<'_>,
    macs: &[Field2_128; super::mac::TOTAL_MAC_VALUES],
    av: &Field2_128,
) {
    for i in 0..super::mac::TOTAL_MAC_VALUES {
        view.mac_region[i] = macs[i];
    }
    view.mac_region[super::mac::TOTAL_MAC_VALUES] = *av;
}

/// Write the post-commit MAC values + `av` challenge into the SIG-circuit
/// public-input statement's MAC region. Each `Field2_128` value is
/// bit-decomposed LSB-first into 128 `FieldP256` wires (Fp256Base can't
/// hold a 128-bit GF(2^128) element as one wire). Mirrors C++
/// `push_sig_mac_values` (p7s_zk.cc:2200-2212).
///
/// Wire order:
///   * 8 mac values × 128 bits = 1024 wires (LSB-first per v128)
///   * 1 av × 128 bits          = 128 wires (LSB-first)
///   * total = 1152 wires = SIG_MAC_INPUT_WIRES
pub(crate) fn fill_sig_mac_region(
    view: &mut SplitSigStatement<'_>,
    macs: &[Field2_128; super::mac::TOTAL_MAC_VALUES],
    av: &Field2_128,
) {
    let mut wire_idx = 0usize;
    for mac in macs.iter() {
        for bit in mac.iter_bits() {
            view.mac_region[wire_idx] =
                if bit { FieldP256::ONE } else { FieldP256::ZERO };
            wire_idx += 1;
        }
    }
    for bit in av.iter_bits() {
        view.mac_region[wire_idx] =
            if bit { FieldP256::ONE } else { FieldP256::ZERO };
        wire_idx += 1;
    }
    debug_assert_eq!(wire_idx, SIG_MAC_INPUT_WIRES);
}

/// Allocate and fully-fill a hash-side public-input region. Returns a
/// `Vec<Field2_128>` pre-sized to `HASH_PUB_TOTAL` with the public region
/// initialized; the MAC sub-region is left at `Field2_128::ZERO` placeholders
/// (overwritten post-commit by `fill_hash_mac_region`).
///
/// Shared by both prover (sub-PR 8) and verifier (sub-PR 9) — must be
/// reachable under `--no-default-features --features verifier`, hence its
/// placement here in `layout.rs` rather than the prover-gated
/// `witness_fill.rs`.
pub(crate) fn build_hash_public_region(pub_: &ParsedPublic) -> alloc::vec::Vec<Field2_128> {
    let mut buf = alloc::vec![Field2_128::ZERO; HASH_PUB_TOTAL];
    {
        let mut view = split_hash_statement(&mut buf);
        fill_hash_public_pre_mac(&mut view, pub_);
    }
    buf
}

/// Allocate and fully-fill a sig-side public-input region. Returns a
/// `Vec<FieldP256>` pre-sized to `SIG_PUB_TOTAL`; the MAC sub-region is left
/// at `FieldP256::ZERO` placeholders (overwritten post-commit by
/// `fill_sig_mac_region`).
pub(crate) fn build_sig_public_region(pub_: &ParsedPublic) -> alloc::vec::Vec<FieldP256> {
    let mut buf = alloc::vec![FieldP256::ZERO; SIG_PUB_TOTAL];
    {
        let mut view = split_sig_statement(&mut buf);
        fill_sig_public_pre_mac(&mut view, pub_);
    }
    buf
}

// ---------------------------------------------------------------------------
// Bit-pushing primitives (mirror C++ push_v8 / push_uint / push_target)
// ---------------------------------------------------------------------------

/// SHA-target view: bit `j` of the 256-wire output corresponds to bit
/// `j % 8` of byte `(255 - j) / 8` of the 32-byte digest. Big-endian-byte
/// / LSB-bit ordering — matches FlatSHA256Circuit's `assert_hash` layout.
/// C++ source: `p7s_zk.cc:1571 push_target`.
fn push_target_be(out: &mut [Field2_128; 256], digest: &[u8; 32]) {
    for j in 0..256 {
        let byte_idx = (255 - j) / 8;
        let bit_idx = j % 8;
        let bit = (digest[byte_idx] >> bit_idx) & 1;
        out[j] = if bit == 1 { Field2_128::ONE } else { Field2_128::ZERO };
    }
}

/// Byte-by-byte LSB-first bit decomposition. Each byte expands into
/// 8 wires `[bit0, bit1, ..., bit7]`. Matches C++ `push_v8`
/// (`p7s_zk.cc:1559`) / `push_pk_public` / `push_nonce_public`.
fn push_bytes_lsb_first<const N_BITS: usize>(out: &mut [Field2_128; N_BITS], bytes: &[u8]) {
    debug_assert_eq!(bytes.len() * 8, N_BITS);
    for (i, &byte) in bytes.iter().enumerate() {
        for bit_idx in 0..8 {
            let bit = (byte >> bit_idx) & 1;
            out[i * 8 + bit_idx] =
                if bit == 1 { Field2_128::ONE } else { Field2_128::ZERO };
        }
    }
}

/// k-bit LSB-first u32 expansion. Matches C++ `push_uint`
/// (`p7s_zk.cc:1564`); used for the v32 trust_anchor_index region.
fn push_uint_lsb_first_u32<const K: usize>(out: &mut [Field2_128; K], value: u32) {
    for j in 0..K {
        let bit = ((value >> j) & 1) as u8;
        out[j] = if bit == 1 { Field2_128::ONE } else { Field2_128::ZERO };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn dummy_public() -> ParsedPublic {
        ParsedPublic {
            context_hash: [0xAB; 32],
            pk: [0x55; PK_BYTES],
            nonce: [0xCD; NONCE_BYTES],
            nullifier: [0x11; NULLIFIER_LEN],
            enroll_commit: [0x22; ENROLL_COMMIT_LEN],
            enroll_nullifier: [0x33; ENROLL_NULLIFIER_LEN],
            trust_anchor_index: 1,
        }
    }

    #[test]
    fn hash_pub_total_matches_cpp_constant() {
        // Mirrors `static_assert(kHashPubTotal == 1842)` (p7s_zk.cc:489).
        assert_eq!(HASH_PUB_TOTAL, 1842);
        assert_eq!(HASH_PUB_PRE_MAC, 1833);
        assert_eq!(HASH_MAC_INPUT_WIRES, 9);
    }

    #[test]
    fn sig_pub_total_matches_cpp_constant() {
        // Mirrors `static_assert(kSigPubTotal == 1154)` (p7s_zk.cc:562).
        assert_eq!(SIG_PUB_TOTAL, 1154);
        assert_eq!(SIG_MAC_INPUT_WIRES, 1152);
        assert_eq!(SIG_MAC_INDEX, 2);
    }

    #[test]
    fn split_hash_statement_does_not_panic() {
        let mut buf: Vec<Field2_128> = vec![Field2_128::ZERO; HASH_PUB_TOTAL];
        let _ = split_hash_statement(&mut buf);
    }

    #[test]
    fn split_sig_statement_does_not_panic() {
        let mut buf: Vec<FieldP256> = vec![FieldP256::ZERO; SIG_PUB_TOTAL];
        let _ = split_sig_statement(&mut buf);
    }

    #[test]
    fn fill_hash_public_pre_mac_writes_implicit_one_and_index() {
        let mut buf: Vec<Field2_128> = vec![Field2_128::ZERO; HASH_PUB_TOTAL];
        let pub_ = dummy_public();
        let mut view = split_hash_statement(&mut buf);
        fill_hash_public_pre_mac(&mut view, &pub_);
        // Implicit one slot.
        assert_eq!(buf[0], Field2_128::ONE);
        // trust_anchor_index = 1 → bit0 = 1, bits 1..32 = 0.
        assert_eq!(buf[1801], Field2_128::ONE);
        for j in 1..32 {
            assert_eq!(buf[1801 + j], Field2_128::ZERO);
        }
        // MAC region untouched (placeholder zeros).
        for w in &buf[HASH_MAC_INDEX..HASH_PUB_TOTAL] {
            assert_eq!(*w, Field2_128::ZERO);
        }
    }

    #[test]
    fn fill_hash_public_pre_mac_context_hash_byte_bit_ordering() {
        // context_hash byte 31 controls wires [248..256) within the
        // 256-wire context_hash region (which starts at wire 1).
        // 0xA5 = 0b1010_0101 → LSB-first bits: 1,0,1,0,0,1,0,1.
        let mut pub_ = dummy_public();
        pub_.context_hash = [0; 32];
        pub_.context_hash[31] = 0xA5;
        let mut buf: Vec<Field2_128> = vec![Field2_128::ZERO; HASH_PUB_TOTAL];
        let mut view = split_hash_statement(&mut buf);
        fill_hash_public_pre_mac(&mut view, &pub_);
        let base = 1 + 248;
        let expected = [1u8, 0, 1, 0, 0, 1, 0, 1];
        for (i, &b) in expected.iter().enumerate() {
            let want = if b == 1 { Field2_128::ONE } else { Field2_128::ZERO };
            assert_eq!(buf[base + i], want, "context_hash bit {i} mismatch");
        }
    }

    #[test]
    fn fill_hash_public_pre_mac_pk_byte_bit_ordering() {
        // pk byte 0 controls wires [257..265). 0x55 = 0b0101_0101 →
        // LSB-first: 1,0,1,0,1,0,1,0.
        let mut pub_ = dummy_public();
        pub_.pk = [0; PK_BYTES];
        pub_.pk[0] = 0x55;
        let mut buf: Vec<Field2_128> = vec![Field2_128::ZERO; HASH_PUB_TOTAL];
        let mut view = split_hash_statement(&mut buf);
        fill_hash_public_pre_mac(&mut view, &pub_);
        let base = 1 + 256;
        let expected = [1u8, 0, 1, 0, 1, 0, 1, 0];
        for (i, &b) in expected.iter().enumerate() {
            let want = if b == 1 { Field2_128::ONE } else { Field2_128::ZERO };
            assert_eq!(buf[base + i], want, "pk byte 0 bit {i} mismatch");
        }
    }

    #[test]
    fn fill_sig_public_pre_mac_lifts_trust_anchor_index() {
        let mut buf: Vec<FieldP256> = vec![FieldP256::ZERO; SIG_PUB_TOTAL];
        let pub_ = dummy_public();
        let mut view = split_sig_statement(&mut buf);
        fill_sig_public_pre_mac(&mut view, &pub_);
        assert_eq!(buf[0], FieldP256::ONE);
        assert_eq!(buf[1], FieldP256::from_u128(1));
        // MAC region untouched.
        for w in &buf[SIG_MAC_INDEX..SIG_PUB_TOTAL] {
            assert_eq!(*w, FieldP256::ZERO);
        }
    }

    #[test]
    fn fill_sig_public_pre_mac_index_zero_round_trip() {
        let mut buf: Vec<FieldP256> = vec![FieldP256::ZERO; SIG_PUB_TOTAL];
        let mut pub_ = dummy_public();
        pub_.trust_anchor_index = 0;
        let mut view = split_sig_statement(&mut buf);
        fill_sig_public_pre_mac(&mut view, &pub_);
        assert_eq!(buf[1], FieldP256::ZERO);
    }

    #[test]
    fn fill_hash_mac_region_writes_macs_then_av() {
        let mut buf: Vec<Field2_128> = vec![Field2_128::ZERO; HASH_PUB_TOTAL];
        let macs: [Field2_128; super::super::mac::TOTAL_MAC_VALUES] = [
            Field2_128::from_u128(11),
            Field2_128::from_u128(12),
            Field2_128::from_u128(13),
            Field2_128::from_u128(14),
            Field2_128::from_u128(15),
            Field2_128::from_u128(16),
            Field2_128::from_u128(17),
            Field2_128::from_u128(18),
        ];
        let av = Field2_128::from_u128(99);
        let mut view = split_hash_statement(&mut buf);
        fill_hash_mac_region(&mut view, &macs, &av);
        for i in 0..super::super::mac::TOTAL_MAC_VALUES {
            assert_eq!(buf[HASH_MAC_INDEX + i], macs[i]);
        }
        assert_eq!(
            buf[HASH_MAC_INDEX + super::super::mac::TOTAL_MAC_VALUES],
            av
        );
    }

    #[test]
    fn fill_sig_mac_region_bit_decomposes_lsb_first() {
        let mut buf: Vec<FieldP256> = vec![FieldP256::ZERO; SIG_PUB_TOTAL];
        // Single non-zero mac value at slot 0 = 0x05 = 0b101 → bits (LSB-first)
        // 1, 0, 1, 0, 0, 0, ...
        let mut macs = [Field2_128::ZERO; super::super::mac::TOTAL_MAC_VALUES];
        macs[0] = Field2_128::from_u128(0x05);
        let av = Field2_128::ZERO;
        let mut view = split_sig_statement(&mut buf);
        fill_sig_mac_region(&mut view, &macs, &av);
        // mac[0] occupies wires [SIG_MAC_INDEX .. SIG_MAC_INDEX+128).
        let base = SIG_MAC_INDEX;
        assert_eq!(buf[base + 0], FieldP256::ONE);
        assert_eq!(buf[base + 1], FieldP256::ZERO);
        assert_eq!(buf[base + 2], FieldP256::ONE);
        for j in 3..128 {
            assert_eq!(buf[base + j], FieldP256::ZERO, "bit {j} should be zero");
        }
        // Remaining 7 macs + av all zero → all subsequent wires zero.
        for j in 128..SIG_MAC_INPUT_WIRES {
            assert_eq!(buf[base + j], FieldP256::ZERO);
        }
    }

    #[test]
    fn fill_sig_mac_region_av_lands_after_eight_macs() {
        let mut buf: Vec<FieldP256> = vec![FieldP256::ZERO; SIG_PUB_TOTAL];
        let macs = [Field2_128::ZERO; super::super::mac::TOTAL_MAC_VALUES];
        let av = Field2_128::from_u128(0x01); // bit 0 set
        let mut view = split_sig_statement(&mut buf);
        fill_sig_mac_region(&mut view, &macs, &av);
        // av occupies wires [SIG_MAC_INDEX + 8*128 .. SIG_MAC_INDEX + 9*128).
        let av_base = SIG_MAC_INDEX + super::super::mac::TOTAL_MAC_VALUES * 128;
        assert_eq!(buf[av_base + 0], FieldP256::ONE);
        for j in 1..128 {
            assert_eq!(buf[av_base + j], FieldP256::ZERO);
        }
    }
}
