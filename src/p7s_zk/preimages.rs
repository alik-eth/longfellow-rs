//! v12 nullifier / enroll-commit / enroll-nullifier preimage SHA witness builders.
//!
//! Mirrors C++ `p7s_zk.cc:2520-2573`. Each builder constructs the canonical
//! preimage byte buffer for one of the three v12 SHA-256 derivations and runs
//! the off-circuit SHA witness pass via [`compute_sha_witness`].
//!
//! Preimages:
//!   * per-app nullifier:    `0x01 || holder_seed[32] || context_hash[32]`  (65 bytes, 2 SHA blocks)
//!   * enroll commit:        `0x03 || holder_seed[32]`                       (33 bytes, 1 SHA block)
//!   * enroll nullifier:     `0x02 || stable_id[16] || ENROLL_DOMAIN_SEP[16]` (33 bytes, 1 SHA block)

use crate::p7s_zk::sha256_witness::{ShaWitness, compute_sha_witness};

/// Domain-separation tag for the per-app nullifier.
///
/// C++: `kDsTagPerAppNullifier = 0x01` (`p7s_hash.h:159`).
pub(crate) const DS_TAG_PER_APP_NULLIFIER: u8 = 0x01;

/// Domain-separation tag for the enroll nullifier.
///
/// C++: `kDsTagEnrollNullifier = 0x02` (`p7s_hash.h:160`).
pub(crate) const DS_TAG_ENROLL_NULLIFIER: u8 = 0x02;

/// Domain-separation tag for the enroll commit.
///
/// C++: `kDsTagEnrollCommit = 0x03` (`p7s_hash.h:161`).
pub(crate) const DS_TAG_ENROLL_COMMIT: u8 = 0x03;

/// `"zk-eidas-enroll!"` — 16 ASCII bytes, no NUL padding.
///
/// C++: `kEnrollDomainSep` (`p7s_hash.h:164-167`).
pub(crate) const ENROLL_DOMAIN_SEP: [u8; 16] = [
    0x7a, 0x6b, 0x2d, 0x65, 0x69, 0x64, 0x61, 0x73, 0x2d, 0x65, 0x6e, 0x72, 0x6f, 0x6c, 0x6c, 0x21,
];

/// Holder secret length (32 bytes).
///
/// C++: `kHolderSeedLen = 32` (`p7s_hash.h:154`).
pub(crate) const HOLDER_SEED_LEN: usize = 32;

/// Application context hash length (32 bytes).
///
/// C++: `kContextHashLen = 32` (`p7s_hash.h:155`).
pub(crate) const CONTEXT_HASH_LEN: usize = 32;

/// Subject-SN anchor length within cert_tbs (9 bytes).
///
/// C++: `kSubjectSnAnchorLen = 9` (`p7s_circuit.h:144`).
pub(crate) const SUBJECT_SN_ANCHOR_LEN: usize = 9;

/// Stable-ID length, sourced from cert_tbs after the SN anchor (16 bytes).
///
/// C++: `kStableIdLen = 16` (`p7s_circuit.h:143`).
pub(crate) const STABLE_ID_LEN: usize = 16;

/// SHA block count for the per-app nullifier preimage (2 blocks for 65 raw bytes).
pub(crate) const NULLIFIER_SHA_BLOCKS: usize = 2;

/// SHA block count for the enroll commit preimage (1 block for 33 raw bytes).
pub(crate) const ENROLL_COMMIT_SHA_BLOCKS: usize = 1;

/// SHA block count for the enroll nullifier preimage (1 block for 33 raw bytes).
pub(crate) const ENROLL_NULLIFIER_SHA_BLOCKS: usize = 1;

/// Build the per-app nullifier SHA witness.
///
/// Preimage: `[0x01 | holder_seed | context_hash]`, 65 bytes total → 2 SHA blocks.
///
/// C++: `p7s_zk.cc:2529-2535`.
pub(crate) fn build_nullifier_sha_witness(
    holder_seed: &[u8; HOLDER_SEED_LEN],
    context_hash: &[u8; CONTEXT_HASH_LEN],
) -> ShaWitness {
    let mut raw = [0u8; 1 + HOLDER_SEED_LEN + CONTEXT_HASH_LEN];
    raw[0] = DS_TAG_PER_APP_NULLIFIER;
    raw[1..1 + HOLDER_SEED_LEN].copy_from_slice(holder_seed);
    raw[1 + HOLDER_SEED_LEN..].copy_from_slice(context_hash);
    compute_sha_witness(&raw, NULLIFIER_SHA_BLOCKS)
}

/// Build the enroll-commit SHA witness.
///
/// Preimage: `[0x03 | holder_seed]`, 33 bytes total → 1 SHA block.
///
/// C++: `p7s_zk.cc:2548-2553`.
pub(crate) fn build_enroll_commit_sha_witness(
    holder_seed: &[u8; HOLDER_SEED_LEN],
) -> ShaWitness {
    let mut raw = [0u8; 1 + HOLDER_SEED_LEN];
    raw[0] = DS_TAG_ENROLL_COMMIT;
    raw[1..].copy_from_slice(holder_seed);
    compute_sha_witness(&raw, ENROLL_COMMIT_SHA_BLOCKS)
}

/// Build the enroll-nullifier SHA witness.
///
/// Preimage: `[0x02 | stable_id | ENROLL_DOMAIN_SEP]`, 33 bytes total → 1 SHA block.
///
/// `stable_id` is sourced from cert_tbs at
/// `cert_tbs[subject_sn_offset_in_tbs + SUBJECT_SN_ANCHOR_LEN ..
/// + SUBJECT_SN_ANCHOR_LEN + STABLE_ID_LEN]` (the same routed window
/// invariant 12 binds via `sn_window`).
///
/// C++: `p7s_zk.cc:2562-2571`.
pub(crate) fn build_enroll_nullifier_sha_witness(
    stable_id: &[u8; STABLE_ID_LEN],
) -> ShaWitness {
    let mut raw = [0u8; 1 + STABLE_ID_LEN + ENROLL_DOMAIN_SEP.len()];
    raw[0] = DS_TAG_ENROLL_NULLIFIER;
    raw[1..1 + STABLE_ID_LEN].copy_from_slice(stable_id);
    raw[1 + STABLE_ID_LEN..].copy_from_slice(&ENROLL_DOMAIN_SEP);
    compute_sha_witness(&raw, ENROLL_NULLIFIER_SHA_BLOCKS)
}

/// Extract `stable_id` from a `cert_tbs` slice at the given subject-SN offset.
///
/// `subject_sn_offset_in_tbs` points at the SN anchor's first byte; the stable-ID
/// is the 16 bytes that immediately follow the 9-byte anchor.
///
/// Returns `None` if the offset/length combination would read past `cert_tbs`.
pub(crate) fn extract_stable_id(
    cert_tbs: &[u8],
    subject_sn_offset_in_tbs: usize,
) -> Option<[u8; STABLE_ID_LEN]> {
    let start = subject_sn_offset_in_tbs.checked_add(SUBJECT_SN_ANCHOR_LEN)?;
    let end = start.checked_add(STABLE_ID_LEN)?;
    if end > cert_tbs.len() {
        return None;
    }
    let mut out = [0u8; STABLE_ID_LEN];
    out.copy_from_slice(&cert_tbs[start..end]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sha256_be(input: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(input);
        h.finalize().into()
    }

    #[test]
    fn nullifier_digest_matches_concat_sha256() {
        let holder_seed = [0xa5u8; HOLDER_SEED_LEN];
        let context_hash = [0x5au8; CONTEXT_HASH_LEN];
        let mut expected_preimage = vec![DS_TAG_PER_APP_NULLIFIER];
        expected_preimage.extend_from_slice(&holder_seed);
        expected_preimage.extend_from_slice(&context_hash);
        let expected = sha256_be(&expected_preimage);

        let sw = build_nullifier_sha_witness(&holder_seed, &context_hash);
        assert_eq!(sw.digest, expected);
        assert_eq!(sw.numb, 2);
    }

    #[test]
    fn enroll_commit_digest_matches_concat_sha256() {
        let holder_seed = [0x33u8; HOLDER_SEED_LEN];
        let mut expected_preimage = vec![DS_TAG_ENROLL_COMMIT];
        expected_preimage.extend_from_slice(&holder_seed);
        let expected = sha256_be(&expected_preimage);

        let sw = build_enroll_commit_sha_witness(&holder_seed);
        assert_eq!(sw.digest, expected);
        assert_eq!(sw.numb, 1);
    }

    #[test]
    fn enroll_nullifier_digest_matches_concat_sha256() {
        let stable_id = [0x11u8; STABLE_ID_LEN];
        let mut expected_preimage = vec![DS_TAG_ENROLL_NULLIFIER];
        expected_preimage.extend_from_slice(&stable_id);
        expected_preimage.extend_from_slice(&ENROLL_DOMAIN_SEP);
        let expected = sha256_be(&expected_preimage);

        let sw = build_enroll_nullifier_sha_witness(&stable_id);
        assert_eq!(sw.digest, expected);
        assert_eq!(sw.numb, 1);
    }

    #[test]
    fn enroll_domain_sep_is_zk_eidas_enroll_bang() {
        // Documents the domain-separator string. ASCII "zk-eidas-enroll!"
        assert_eq!(&ENROLL_DOMAIN_SEP, b"zk-eidas-enroll!");
    }

    #[test]
    fn extract_stable_id_returns_window_after_anchor() {
        let mut cert_tbs = [0u8; 64];
        // Place a recognizable pattern at offsets 5+9..5+9+16 = 14..30.
        for i in 0..STABLE_ID_LEN {
            cert_tbs[5 + SUBJECT_SN_ANCHOR_LEN + i] = (i as u8) + 0x40;
        }
        let extracted = extract_stable_id(&cert_tbs, 5).unwrap();
        for i in 0..STABLE_ID_LEN {
            assert_eq!(extracted[i], (i as u8) + 0x40);
        }
    }

    #[test]
    fn extract_stable_id_rejects_oob_offset() {
        let cert_tbs = [0u8; 24];
        // offset 5 + 9 + 16 = 30 > 24 → rejected
        assert!(extract_stable_id(&cert_tbs, 5).is_none());
    }
}
