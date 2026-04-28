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

/// Wire-format schema version baked into both blobs. v12 is the
/// holder-bound nullifier schema shipped 2026-04-28.
pub const BLOB_SCHEMA_VERSION: u32 = 12;

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

/// X.520 serialNumber stable-ID byte length (DIIA RNOKPP: `TINUA-` + 10 digits).
pub const STABLE_ID_LEN: usize = 16;
/// 9-byte X.520 serialNumber attribute DER prefix.
pub const SUBJECT_SN_ANCHOR_LEN: usize = 9;
/// Anchor + value = 9 + 16 = 25 bytes.
pub const SUBJECT_SN_WINDOW_LEN: usize = SUBJECT_SN_ANCHOR_LEN + STABLE_ID_LEN;

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
