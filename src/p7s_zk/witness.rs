//! Parsed witness blob — owned, host-side mirror of the C++
//! `ParsedWitness` struct in `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc`.
//!
//! Field order mirrors the on-the-wire blob layout exactly so the
//! parser can read fields top-to-bottom without an intermediate
//! lookup table. Sizes match `layout.rs` constants.

use super::layout::*;
use alloc::vec::Vec;

/// A parsed v12 witness blob ready to be fed to the prover.
///
/// Fixed-size fields use `[u8; N]` to keep the layout obvious and
/// avoid a separate length wire on the Rust side; raw lengths come
/// from the explicit `*_len` fields.
#[derive(Debug, Clone)]
pub struct ParsedWitness {
    /// Real raw length of `context_bytes` (the value that went into
    /// SHA-256 to produce `context_hash`).
    pub context_len: u32,
    /// `context_bytes` zero-padded to `CONTEXT_MAX_BYTES`.
    pub context: [u8; CONTEXT_MAX_BYTES],

    /// Real raw length of `signed_content` (the QKB binding JSON).
    pub signed_content_len: u32,
    /// `signed_content` zero-padded to `MAX_SIGNED_CONTENT`.
    /// The host filler SHA-pads in-place before feeding the circuit;
    /// this Rust struct holds the raw padded buffer the C++ side
    /// emits via `to_ffi_bytes()`.
    pub signed_content: Vec<u8>,

    /// Offset of `pk_hex` inside `signed_content`. Bound: + PK_HEX_LEN
    /// must fit within `MAX_SIGNED_CONTENT`.
    pub json_pk_offset: u32,
    /// 130 ASCII lowercase hex chars (decodes to a 65-byte SEC1 pubkey).
    pub pk_hex: [u8; PK_HEX_LEN],

    /// Offset of `nonce_hex` inside `signed_content`.
    pub json_nonce_offset: u32,
    /// 64 ASCII lowercase hex chars (decodes to a 32-byte nonce).
    pub nonce_hex: [u8; NONCE_HEX_LEN],

    /// Offset of `context_bytes` inside `signed_content`.
    pub json_context_offset: u32,

    /// Offset of the declaration phrase inside `signed_content`.
    pub json_declaration_offset: u32,

    /// v12: offset of `holder_seed_commit` hex inside `signed_content`.
    pub json_holder_seed_commit_offset: u32,
    /// v12: 64 ASCII lowercase hex chars (decodes to a 32-byte commit).
    pub holder_seed_commit_hex: [u8; HOLDER_SEED_COMMIT_HEX_LEN],

    /// Prover-claimed `SHA-256(signed_content)`.
    pub message_digest: [u8; MESSAGE_DIGEST_LEN],

    /// Real raw length of `cert_tbs`.
    pub cert_tbs_len: u32,
    /// Offset of the SPKI SEQUENCE 0x30 tag inside `cert_tbs`.
    pub cert_tbs_spki_offset: u32,
    /// `cert_tbs` zero-padded to `CERT_TBS_MAX_BYTES`.
    pub cert_tbs: Vec<u8>,
    /// Cert signature `r` scalar (big-endian 32 bytes).
    pub cert_sig_r: [u8; ECDSA_SCALAR_LEN],
    /// Cert signature `s` scalar (big-endian 32 bytes).
    pub cert_sig_s: [u8; ECDSA_SCALAR_LEN],

    /// Real raw length of `signed_attrs`.
    pub signed_attrs_len: u32,
    /// Offset of the messageDigest Attribute SEQUENCE tag (0x30)
    /// inside `signed_attrs`.
    pub signed_attrs_md_offset: u32,
    /// `signed_attrs` zero-padded to `SIGNED_ATTRS_MAX_BYTES`.
    /// First raw byte must be `0xA0` (CAdES `[0] IMPLICIT` tag).
    pub signed_attrs: Vec<u8>,
    /// Content signature `r` scalar (big-endian 32 bytes).
    pub content_sig_r: [u8; ECDSA_SCALAR_LEN],
    /// Content signature `s` scalar (big-endian 32 bytes).
    pub content_sig_s: [u8; ECDSA_SCALAR_LEN],

    /// Offset of the 9-byte X.520 serialNumber DER anchor inside `cert_tbs`.
    pub subject_sn_offset_in_tbs: u32,
    /// Offset of the outer Subject DN SEQUENCE inside `cert_tbs`.
    pub subject_dn_start_offset_in_tbs: u32,
    /// Index into the compile-time `kTrustAnchors[]` table (0 selects
    /// TestAnchorA, 1 selects TestAnchorB).
    pub trust_anchor_index: u32,

    /// v12: 32-byte holder secret. Opaque entropy; the in-circuit
    /// invariants 13/14 prove the holder used the seed for which the
    /// credential was issued.
    pub holder_seed: [u8; HOLDER_SEED_LEN],
}
