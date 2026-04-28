//! Parsed public blob — owned, host-side mirror of the C++
//! `ParsedPublic` struct in `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc`.
//!
//! Field order mirrors the on-the-wire blob layout exactly. v12 length
//! is 233 bytes (4 schema + 32 context_hash + 65 pk + 32 nonce + 32
//! nullifier + 32 enroll_commit + 32 enroll_nullifier + 4
//! trust_anchor_index).

use super::layout::*;

/// A parsed v12 public blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPublic {
    /// `SHA-256(context_bytes)` from invariant 9.
    pub context_hash: [u8; 32],
    /// Decoded SEC1 uncompressed P-256 public key (`04 || X || Y`).
    pub pk: [u8; PK_BYTES],
    /// Decoded freshness nonce.
    pub nonce: [u8; NONCE_BYTES],
    /// v11 invariant 7 public output. v12 keeps the field shape; only
    /// the SHA preimage shape changed (now `0x01 || holder_seed ||
    /// context_hash`).
    pub nullifier: [u8; NULLIFIER_LEN],
    /// v12 invariant 14 public output: `SHA-256(0x03 || holder_seed)`.
    pub enroll_commit: [u8; ENROLL_COMMIT_LEN],
    /// v12 invariant 12 public output:
    /// `SHA-256(0x02 || stable_id || ENROLL_DOMAIN_SEP)`.
    pub enroll_nullifier: [u8; ENROLL_NULLIFIER_LEN],
    /// Index into the compile-time trust-anchor table.
    pub trust_anchor_index: u32,
}
