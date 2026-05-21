//! v12 nullifier / enroll-commit / enroll-nullifier preimage SHA witness builders.
//!
//! Mirrors C++ `p7s_zk.cc:2520-2573`. Each builder constructs the canonical
//! preimage byte buffer for one of the three v12 SHA-256 derivations and runs
//! the off-circuit SHA witness pass via [`compute_sha_witness`].
//!
//! Preimages:
//!   * per-app nullifier:    `0x01 || holder_seed[32] || context_hash[32]`  (65 bytes, 2 SHA blocks)
//!   * enroll commit:        `0x03 || holder_seed[32]`                       (33 bytes, 1 SHA block)
//!   * enroll nullifier:     `0x02 || stable_id[0..L] || ENROLL_DOMAIN_SEP[16]` (v13: 1 + L + 16
//!     bytes, L in [8, 37], always 1 SHA block; no length-prefix byte, so L=16 is
//!     byte-identical to the v12 preimage)

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

/// Legacy DIIA RNOKPP stable-ID length (16 bytes) — retained as the
/// canonical UA regression length and used by the unit tests below.
pub(crate) const STABLE_ID_LEN: usize = 16;

/// v13 (Task #37) — minimum stable-ID value length.
///
/// C++: `kStableIdMinLen = 8` (`p7s_circuit.h`).
pub(crate) const STABLE_ID_MIN_LEN: usize = 8;

/// v13 (Task #37) — maximum stable-ID value length.
///
/// C++: `kStableIdMaxLen = 37` (`p7s_circuit.h`).
pub(crate) const STABLE_ID_MAX_LEN: usize = 37;

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

/// Build the enroll-nullifier SHA witness (v13, variable length).
///
/// Preimage: `[0x02 | stable_id[0..L] | ENROLL_DOMAIN_SEP]`, `1 + L +
/// 16` bytes total (L in `[8, 37]`) → always 1 SHA block. No
/// length-prefix byte, so for `L == 16` the preimage is byte-identical
/// to the v12 fixed-length construction.
///
/// `stable_id` is sourced from cert_tbs at
/// `cert_tbs[subject_sn_offset_in_tbs + SUBJECT_SN_ANCHOR_LEN ..
/// + SUBJECT_SN_ANCHOR_LEN + L]` (the same routed window invariant 12
/// binds via `sn_window`).
///
/// C++: `p7s_zk.cc` v13 invariant-12 witness fill.
pub(crate) fn build_enroll_nullifier_sha_witness(stable_id: &[u8]) -> ShaWitness {
    debug_assert!(
        stable_id.len() <= STABLE_ID_MAX_LEN,
        "stable_id exceeds STABLE_ID_MAX_LEN"
    );
    let l = stable_id.len();
    let mut raw = [0u8; 1 + STABLE_ID_MAX_LEN + ENROLL_DOMAIN_SEP.len()];
    raw[0] = DS_TAG_ENROLL_NULLIFIER;
    raw[1..1 + l].copy_from_slice(stable_id);
    raw[1 + l..1 + l + ENROLL_DOMAIN_SEP.len()].copy_from_slice(&ENROLL_DOMAIN_SEP);
    compute_sha_witness(
        &raw[..1 + l + ENROLL_DOMAIN_SEP.len()],
        ENROLL_NULLIFIER_SHA_BLOCKS,
    )
}

/// Extract the variable-length `stable_id` from a `cert_tbs` slice.
///
/// `subject_sn_offset_in_tbs` points at the 9-byte SN anchor's first
/// byte; the PrintableString length `L` lives in anchor byte 8
/// (`cert_tbs[subject_sn_offset_in_tbs + 8]`), and the stable-ID value
/// is the `L` bytes immediately after the anchor.
///
/// Returns `None` if `L` is outside the v13 range `[STABLE_ID_MIN_LEN,
/// STABLE_ID_MAX_LEN]` or the offset/length would read past `cert_tbs`.
pub(crate) fn extract_stable_id(
    cert_tbs: &[u8],
    subject_sn_offset_in_tbs: usize,
) -> Option<&[u8]> {
    let len_idx = subject_sn_offset_in_tbs.checked_add(8)?;
    let l = *cert_tbs.get(len_idx)? as usize;
    if !(STABLE_ID_MIN_LEN..=STABLE_ID_MAX_LEN).contains(&l) {
        return None;
    }
    let start = subject_sn_offset_in_tbs.checked_add(SUBJECT_SN_ANCHOR_LEN)?;
    let end = start.checked_add(l)?;
    if end > cert_tbs.len() {
        return None;
    }
    Some(&cert_tbs[start..end])
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
        // Variable-length (v13): cover the min, the legacy-16, and the
        // max — each must hash to a plain SHA-256 of the concatenated
        // preimage and stay within a single block.
        for l in [STABLE_ID_MIN_LEN, STABLE_ID_LEN, STABLE_ID_MAX_LEN] {
            let stable_id = vec![0x11u8; l];
            let mut expected_preimage = vec![DS_TAG_ENROLL_NULLIFIER];
            expected_preimage.extend_from_slice(&stable_id);
            expected_preimage.extend_from_slice(&ENROLL_DOMAIN_SEP);
            let expected = sha256_be(&expected_preimage);

            let sw = build_enroll_nullifier_sha_witness(&stable_id);
            assert_eq!(sw.digest, expected, "L={l}");
            assert_eq!(sw.numb, 1, "L={l}");
        }
    }

    #[test]
    fn enroll_nullifier_len_16_is_v12_byte_identical() {
        // No length-prefix byte → the L=16 v13 preimage equals the v12
        // fixed-length one. Existing UA enrollments carry forward.
        let id16 = [0x11u8; STABLE_ID_LEN];
        let mut v12_preimage = vec![DS_TAG_ENROLL_NULLIFIER];
        v12_preimage.extend_from_slice(&id16);
        v12_preimage.extend_from_slice(&ENROLL_DOMAIN_SEP);
        assert_eq!(
            build_enroll_nullifier_sha_witness(&id16).digest,
            sha256_be(&v12_preimage)
        );
    }

    #[test]
    fn enroll_domain_sep_is_zk_eidas_enroll_bang() {
        // Documents the domain-separator string. ASCII "zk-eidas-enroll!"
        assert_eq!(&ENROLL_DOMAIN_SEP, b"zk-eidas-enroll!");
    }

    #[test]
    fn extract_stable_id_returns_variable_window_after_anchor() {
        // L is read from anchor byte 8. Exercise a 22-byte value.
        let l = 22usize;
        let mut cert_tbs = [0u8; 64];
        cert_tbs[5 + 8] = l as u8; // anchor[8] = L
        for i in 0..l {
            cert_tbs[5 + SUBJECT_SN_ANCHOR_LEN + i] = (i as u8) + 0x40;
        }
        let extracted = extract_stable_id(&cert_tbs, 5).unwrap();
        assert_eq!(extracted.len(), l);
        for i in 0..l {
            assert_eq!(extracted[i], (i as u8) + 0x40);
        }
    }

    #[test]
    fn extract_stable_id_rejects_oob_offset() {
        let mut cert_tbs = [0u8; 24];
        cert_tbs[5 + 8] = 16; // valid L, but 5 + 9 + 16 = 30 > 24
        assert!(extract_stable_id(&cert_tbs, 5).is_none());
    }

    #[test]
    fn extract_stable_id_rejects_out_of_range_length() {
        let mut cert_tbs = [0u8; 64];
        cert_tbs[5 + 8] = 7; // below STABLE_ID_MIN_LEN
        assert!(extract_stable_id(&cert_tbs, 5).is_none());
        cert_tbs[5 + 8] = 38; // above STABLE_ID_MAX_LEN
        assert!(extract_stable_id(&cert_tbs, 5).is_none());
    }
}
