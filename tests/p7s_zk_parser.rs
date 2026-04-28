//! Integration tests for the v12 p7s blob parsers.
//!
//! Lives outside `src/` so it doesn't pull in the (currently broken
//! at baseline) `mdoc_zk` test module — `cargo test -p longfellow --lib`
//! errors-out on pre-existing `Eq` derive issues in `mdoc_zk/layout.rs`,
//! unrelated to this work. Integration tests compile against the lib's
//! public API and don't trigger lib-internal `#[cfg(test)] mod tests`.

use longfellow::{
    ligero::LigeroParameters,
    p7s_zk::{P7sZkProver, P7sZkVerifier, layout::*, parse_public_blob, parse_witness_blob},
};

const SPKI_P256_PREFIX: [u8; SPKI_PREFIX_LEN] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const SUBJECT_SN_ANCHOR: [u8; SUBJECT_SN_ANCHOR_LEN] =
    [0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x10];
const SIGNED_ATTRS_MD_PREFIX: [u8; SIGNED_ATTRS_MD_PREFIX_LEN] = [
    0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04, 0x31, 0x22,
    0x04, 0x20,
];

/// Build a minimal valid v12 witness blob. SPKI placed at cert_tbs[0],
/// SUBJECT_SN at cert_tbs[100..109]; messageDigest prefix at
/// signed_attrs[17..34] (offset 17 because the first byte of
/// signed_attrs MUST be the CAdES `[0] IMPLICIT` tag 0xA0).
fn build_valid_witness_blob() -> Vec<u8> {
    let mut blob = Vec::with_capacity(8192);
    blob.extend_from_slice(&BLOB_SCHEMA_VERSION.to_le_bytes());

    // context.
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&[0u8; CONTEXT_MAX_BYTES]);

    // signed_content.
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&[0u8; MAX_SIGNED_CONTENT]);

    // pk.
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&[b'0'; PK_HEX_LEN]);

    // nonce.
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&[b'0'; NONCE_HEX_LEN]);

    // context offset / declaration offset.
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());

    // holder_seed_commit (v12).
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&[b'0'; HOLDER_SEED_COMMIT_HEX_LEN]);

    // message_digest.
    blob.extend_from_slice(&[0u8; MESSAGE_DIGEST_LEN]);

    // cert_tbs.
    let cert_tbs_len: u32 = 1024;
    blob.extend_from_slice(&cert_tbs_len.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes()); // spki offset

    let mut cert_tbs = [0u8; CERT_TBS_MAX_BYTES];
    cert_tbs[..SPKI_PREFIX_LEN].copy_from_slice(&SPKI_P256_PREFIX);
    cert_tbs[SPKI_PREFIX_LEN] = 0x04; // SEC1 uncompressed-point tag
    cert_tbs[100..100 + SUBJECT_SN_ANCHOR_LEN].copy_from_slice(&SUBJECT_SN_ANCHOR);
    blob.extend_from_slice(&cert_tbs);

    // cert_sig (r, s).
    blob.extend_from_slice(&[0u8; ECDSA_SCALAR_LEN]);
    blob.extend_from_slice(&[0u8; ECDSA_SCALAR_LEN]);

    // signed_attrs.
    let signed_attrs_len: u32 = 512;
    blob.extend_from_slice(&signed_attrs_len.to_le_bytes());
    blob.extend_from_slice(&17u32.to_le_bytes()); // md_offset = 17

    let mut signed_attrs = [0u8; SIGNED_ATTRS_MAX_BYTES];
    signed_attrs[0] = 0xA0;
    signed_attrs[17..17 + SIGNED_ATTRS_MD_PREFIX_LEN]
        .copy_from_slice(&SIGNED_ATTRS_MD_PREFIX);
    blob.extend_from_slice(&signed_attrs);

    // content_sig (r, s).
    blob.extend_from_slice(&[0u8; ECDSA_SCALAR_LEN]);
    blob.extend_from_slice(&[0u8; ECDSA_SCALAR_LEN]);

    // v11 invariant 7 offsets + trust_anchor_index.
    blob.extend_from_slice(&100u32.to_le_bytes()); // subject_sn_offset
    blob.extend_from_slice(&0u32.to_le_bytes()); // subject_dn_start_offset
    blob.extend_from_slice(&0u32.to_le_bytes()); // trust_anchor_index = 0

    // v12 holder_seed.
    blob.extend_from_slice(&[0u8; HOLDER_SEED_LEN]);

    blob
}

fn build_valid_public_blob() -> Vec<u8> {
    let mut blob = Vec::with_capacity(256);
    blob.extend_from_slice(&BLOB_SCHEMA_VERSION.to_le_bytes());
    blob.extend_from_slice(&[0u8; 32]);
    blob.extend_from_slice(&[0u8; PK_BYTES]);
    blob.extend_from_slice(&[0u8; NONCE_BYTES]);
    blob.extend_from_slice(&[0u8; NULLIFIER_LEN]);
    blob.extend_from_slice(&[0u8; ENROLL_COMMIT_LEN]);
    blob.extend_from_slice(&[0u8; ENROLL_NULLIFIER_LEN]);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob
}

#[test]
fn witness_round_trip_minimal() {
    let blob = build_valid_witness_blob();
    let parsed = parse_witness_blob(&blob).expect("minimal valid witness must parse");
    assert_eq!(parsed.context_len, 0);
    assert_eq!(parsed.signed_content_len, 0);
    assert_eq!(parsed.cert_tbs_len, 1024);
    assert_eq!(parsed.signed_attrs_len, 512);
    assert_eq!(parsed.subject_sn_offset_in_tbs, 100);
    assert_eq!(parsed.subject_dn_start_offset_in_tbs, 0);
    assert_eq!(parsed.trust_anchor_index, 0);
    assert_eq!(parsed.holder_seed, [0u8; HOLDER_SEED_LEN]);
}

#[test]
fn witness_rejects_wrong_schema() {
    let mut blob = build_valid_witness_blob();
    blob[0..4].copy_from_slice(&11u32.to_le_bytes());
    let err = parse_witness_blob(&blob).expect_err("wrong schema must reject");
    assert!(
        err.to_string().contains("schema version mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn witness_rejects_bad_spki_prefix() {
    let mut blob = build_valid_witness_blob();
    // cert_tbs lives at byte offset 1386 within the blob; corrupt its first byte.
    let cert_tbs_pos = 1386;
    blob[cert_tbs_pos] ^= 0xff;
    let err = parse_witness_blob(&blob).expect_err("bad SPKI must reject");
    assert!(
        err.to_string().contains("SPKI prefix mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn witness_rejects_trailing_bytes() {
    let mut blob = build_valid_witness_blob();
    blob.push(0xff);
    let err = parse_witness_blob(&blob).expect_err("trailing bytes must reject");
    assert!(
        err.to_string().contains("trailing bytes after parse"),
        "unexpected error: {err}"
    );
}

#[test]
fn witness_rejects_dn_start_after_sn() {
    let mut blob = build_valid_witness_blob();
    let len = blob.len();
    // Tail layout (offsets back from end): holder_seed[32] |
    // trust_anchor_index[4] | subject_dn_start_offset[4] |
    // subject_sn_offset[4]. So dn_start sits at len-40.
    let dn_start_pos = len - 40;
    blob[dn_start_pos..dn_start_pos + 4].copy_from_slice(&200u32.to_le_bytes());
    let err = parse_witness_blob(&blob).expect_err("dn_start >= sn must reject");
    assert!(
        err.to_string()
            .contains("subject_dn_start_offset must precede subject_sn_offset"),
        "unexpected error: {err}"
    );
}

#[test]
fn witness_rejects_oob_trust_anchor() {
    let mut blob = build_valid_witness_blob();
    let len = blob.len();
    let trust_anchor_pos = len - 36;
    blob[trust_anchor_pos..trust_anchor_pos + 4]
        .copy_from_slice(&TRUST_ANCHOR_COUNT.to_le_bytes());
    let err = parse_witness_blob(&blob).expect_err("oob trust_anchor must reject");
    assert!(
        err.to_string().contains("trust_anchor_index"),
        "unexpected error: {err}"
    );
}

#[test]
fn witness_rejects_first_byte_not_a0() {
    let mut blob = build_valid_witness_blob();
    // signed_attrs sits after cert_tbs (1386+4+4+2048+32+32+4+4 = 3514 from start
    // through cert_tbs+sigs+signed_attrs_len+md_offset = body of signed_attrs).
    // Easier: search for the 0xA0 byte and corrupt it.
    // Reverse find: signed_attrs body sits between byte (4+4+32+4+1024+4+130+4+64+4+4
    //                                                  +4+64+32+4+4+2048+32+32+4+4)
    //                                              = 1386 + 32 + 32 + 4 + 4 + 2048 + 32 + 32
    //                                              = 1386 + 2186 = ... messy.
    // The signed_attrs body is the only place we wrote 0xA0; flip it.
    let pos = blob.iter().position(|&b| b == 0xA0).expect("0xA0 must be present");
    blob[pos] = 0x00;
    let err = parse_witness_blob(&blob).expect_err("missing CAdES tag must reject");
    assert!(
        err.to_string()
            .contains("CAdES [0] IMPLICIT tag 0xA0"),
        "unexpected error: {err}"
    );
}

#[test]
fn public_round_trip() {
    let blob = build_valid_public_blob();
    let parsed = parse_public_blob(&blob).expect("minimal valid public must parse");
    assert_eq!(parsed.trust_anchor_index, 0);
    assert_eq!(parsed.context_hash, [0u8; 32]);
    assert_eq!(parsed.nullifier, [0u8; NULLIFIER_LEN]);
    assert_eq!(parsed.enroll_commit, [0u8; ENROLL_COMMIT_LEN]);
    assert_eq!(parsed.enroll_nullifier, [0u8; ENROLL_NULLIFIER_LEN]);
}

#[test]
fn public_rejects_wrong_schema() {
    let mut blob = build_valid_public_blob();
    blob[0..4].copy_from_slice(&11u32.to_le_bytes());
    let err = parse_public_blob(&blob).expect_err("wrong schema must reject");
    assert!(
        err.to_string().contains("schema version mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn public_rejects_oob_trust_anchor() {
    let mut blob = build_valid_public_blob();
    let len = blob.len();
    blob[len - 4..len].copy_from_slice(&TRUST_ANCHOR_COUNT.to_le_bytes());
    let err = parse_public_blob(&blob).expect_err("oob trust_anchor must reject");
    assert!(
        err.to_string().contains("trust_anchor_index"),
        "unexpected error: {err}"
    );
}

#[test]
fn public_rejects_trailing_bytes() {
    let mut blob = build_valid_public_blob();
    blob.push(0x00);
    let err = parse_public_blob(&blob).expect_err("trailing bytes must reject");
    assert!(
        err.to_string().contains("trailing bytes after parse"),
        "unexpected error: {err}"
    );
}

#[test]
fn public_blob_length_is_233() {
    // v12 public blob is documented as 233 bytes (4 schema + 32 ctx_hash
    // + 65 pk + 32 nonce + 32 nullifier + 32 enroll_commit + 32
    // enroll_nullifier + 4 trust_anchor_index).
    assert_eq!(build_valid_public_blob().len(), 233);
}

/// Stub Ligero parameters good enough to exercise the constructor's
/// type-system surface; not the canonical p7s values. Real parameters
/// arrive in #74 or #95.
fn stub_ligero_params() -> LigeroParameters {
    LigeroParameters {
        nreq: 189,
        witnesses_per_row: 64,
        quadratic_constraints_per_row: 64,
        block_size: 256,
        num_columns: 1024,
    }
}

#[test]
fn prover_rejects_empty_circuit_bytes() {
    let params = stub_ligero_params();
    match P7sZkProver::new(&[], params.clone(), params) {
        Ok(_) => panic!("empty circuit bytes must reject"),
        Err(e) => {
            let s = e.to_string();
            assert!(
                s.contains("p7s: failed to decode hash circuit") || s.contains("hash"),
                "unexpected error: {s}"
            );
        }
    }
}

#[test]
fn verifier_rejects_empty_circuit_bytes() {
    let params = stub_ligero_params();
    match P7sZkVerifier::new(&[], params.clone(), params) {
        Ok(_) => panic!("empty circuit bytes must reject"),
        Err(e) => {
            let s = e.to_string();
            assert!(
                s.contains("p7s: failed to decode hash circuit") || s.contains("hash"),
                "unexpected error: {s}"
            );
        }
    }
}
