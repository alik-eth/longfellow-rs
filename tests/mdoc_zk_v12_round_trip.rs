//! Round-trip test for the v12 mdoc verifier path (Task #3 item 7).
//!
//! Loads the canonical v12 mdoc fixture — a real C++-`run_mdoc_prover_v12`
//! proof plus the matching pure-Rust public-input statement blobs —
//! produced by `longfellow-sys`'s `dump_mdoc_v12_fixture` generator
//! (item 6), and asserts the pure-Rust `mdoc_zk::verify_v12_with_circuit`
//! accepts it. A negative test corrupts the proof and asserts rejection.
//!
//! This exercises the no_std-clean verifier path on a real cross-language
//! proof: the proof is C++-generated; the verification is 100% pure Rust
//! (generic Sumcheck + Ligero, circuit-agnostic).
//!
//! The fixture bundles four length-prefixed (u32-LE) sections:
//!   [proof_bytes][hash_statement][signature_statement][transcript]
//! The v12 circuit bytes themselves are the separately-committed
//! `circuits/mdoc_circuit_v12.bin.zst` asset.

use longfellow::{
    circuit_data::mdoc_circuit_v12_decompressed, mdoc_zk::verify_v12_with_circuit,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/mdoc/v12_1attr.bin");

/// Split the fixture into its four length-prefixed sections.
fn parse_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut sections = Vec::new();
    let mut offset = 0usize;
    while offset < FIXTURE.len() {
        let len = u32::from_le_bytes(FIXTURE[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        sections.push(FIXTURE[offset..offset + len].to_vec());
        offset += len;
    }
    assert_eq!(sections.len(), 4, "fixture has 4 sections");
    let mut it = sections.into_iter();
    (
        it.next().unwrap(), // proof
        it.next().unwrap(), // hash statement
        it.next().unwrap(), // signature statement
        it.next().unwrap(), // transcript
    )
}

#[test]
fn mdoc_v12_fixture_present() {
    assert!(!FIXTURE.is_empty(), "v12 mdoc fixture present");
    let (proof, hash_stmt, sig_stmt, transcript) = parse_fixture();
    assert!(!proof.is_empty(), "proof section non-empty");
    assert!(!hash_stmt.is_empty(), "hash statement section non-empty");
    assert!(!sig_stmt.is_empty(), "signature statement section non-empty");
    assert!(!transcript.is_empty(), "transcript section non-empty");
    assert!(
        !mdoc_circuit_v12_decompressed().is_empty(),
        "v12 mdoc circuit asset present"
    );
}

#[test]
fn mdoc_v12_verify_accepts_real_cpp_proof() {
    let (proof, hash_stmt, sig_stmt, transcript) = parse_fixture();
    let circuit_bytes = mdoc_circuit_v12_decompressed();

    let outputs = verify_v12_with_circuit(
        circuit_bytes,
        1, // 1-attribute fixture
        &hash_stmt,
        &sig_stmt,
        &transcript,
        &proof,
    )
    .expect("pure-Rust verify_v12 must accept the C++-generated v12 mdoc proof");

    // The v12 public outputs are non-zero (the prover filled real
    // SHA-256 digests). `enroll_commit` is the holder-seed commitment,
    // deterministic across presentations.
    assert_ne!(outputs.nullifier, [0u8; 32], "nullifier is non-zero");
    assert_ne!(outputs.enroll_commit, [0u8; 32], "enroll_commit is non-zero");
    assert_ne!(
        outputs.enroll_nullifier, [0u8; 32],
        "enroll_nullifier is non-zero"
    );
    // The fixture's holder_seed is the fixed `[0x42; 32]`; enroll_commit
    // = SHA-256(0x03 || holder_seed) is therefore a known constant.
    let expected_enroll_commit = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update([0x03u8]);
        h.update([0x42u8; 32]);
        let d: [u8; 32] = h.finalize().into();
        d
    };
    assert_eq!(
        outputs.enroll_commit, expected_enroll_commit,
        "enroll_commit = SHA-256(0x03 || holder_seed)"
    );
}

#[test]
fn mdoc_v12_verify_rejects_corrupt_proof() {
    let (mut proof, hash_stmt, sig_stmt, transcript) = parse_fixture();
    let circuit_bytes = mdoc_circuit_v12_decompressed();

    // Flip a byte mid-proof — past the leading mac_tags / commitment
    // codec-decode region, inside the Sumcheck/Ligero payload.
    let target = proof.len() * 3 / 4;
    proof[target] ^= 0xFF;

    let result = verify_v12_with_circuit(
        circuit_bytes,
        1,
        &hash_stmt,
        &sig_stmt,
        &transcript,
        &proof,
    );
    assert!(result.is_err(), "corrupt v12 mdoc proof must be rejected");
}

#[test]
fn mdoc_v12_verify_rejects_wrong_attribute_count() {
    let (proof, hash_stmt, sig_stmt, transcript) = parse_fixture();
    let circuit_bytes = mdoc_circuit_v12_decompressed();

    // The fixture is a 1-attribute circuit; claiming 2 attributes must
    // fail (statement-length / circuit-npub mismatch).
    let result = verify_v12_with_circuit(
        circuit_bytes,
        2,
        &hash_stmt,
        &sig_stmt,
        &transcript,
        &proof,
    );
    assert!(
        result.is_err(),
        "wrong attribute count must be rejected before Sumcheck"
    );
}
