//! Integration test for Task #95 work-items 3-5: round-trip
//! `P7sZkProver::prove` → `P7sZkVerifier::verify` over the canonical
//! v12 fixture from #97.
//!
//! Acceptance gate for the bundle: the prover produces non-empty proof
//! bytes; the verifier accepts them and extracts public outputs that
//! match the parsed public blob.
//!
//! Notes:
//!   * Uses the Rust-internal `default_ligero_params_for_circuit` —
//!     fine for Rust↔Rust scope A. Cross-language Rust↔C++ proof-bytes
//!     parity is `#98`'s territory (different `block_enc` selection
//!     among tied minima), out of scope here.
//!   * Run with `--test-threads=1` for ECDSA proving on the 32GB
//!     constrained CI node.

use longfellow::{
    Codec,
    circuit::Circuit,
    fields::{CodecFieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    io::Cursor,
    p7s_zk::{
        P7S_NREQ, P7S_RATE_INV, P7sZkProver, P7sZkVerifier, default_ligero_params_for_circuit,
        parse_public_blob,
    },
};

const COMPRESSED_CIRCUIT: &[u8] =
    include_bytes!("fixtures/p7s_zk/p7s_circuit_v12.bin.zst");
const WITNESS_BLOB: &[u8] =
    include_bytes!("fixtures/p7s/blobs/testanchor_a_v12_witness.bin");
const PUBLIC_BLOB: &[u8] =
    include_bytes!("fixtures/p7s/blobs/testanchor_a_v12_public.bin");

fn load_circuit_bytes() -> Vec<u8> {
    zstd::decode_all(COMPRESSED_CIRCUIT).expect("zstd decode of p7s circuit fixture")
}

/// Construct prover + verifier from the same `circuit_bytes` and Rust-internal
/// optimizer-derived Ligero parameters. Both sides must use identical params
/// for the FS interleave to align.
fn build_prover_and_verifier(circuit_bytes: &[u8]) -> (P7sZkProver, P7sZkVerifier) {
    let mut cursor = Cursor::new(circuit_bytes);
    let hash_circuit = Circuit::<Field2_128>::decode(&mut cursor).unwrap();
    let sig_circuit = Circuit::<FieldP256>::decode(&mut cursor).unwrap();

    let hash_params = default_ligero_params_for_circuit(
        &hash_circuit,
        P7S_RATE_INV,
        P7S_NREQ,
        Field2_128::num_bytes() as u64,
        2,
    );
    let sig_params = default_ligero_params_for_circuit(
        &sig_circuit,
        P7S_RATE_INV,
        P7S_NREQ,
        FieldP256::num_bytes() as u64,
        FieldP256::num_bytes() as u64,
    );

    let prover = P7sZkProver::new(circuit_bytes, hash_params.clone(), sig_params.clone())
        .expect("P7sZkProver::new");
    let verifier = P7sZkVerifier::new(circuit_bytes, hash_params, sig_params)
        .expect("P7sZkVerifier::new");
    (prover, verifier)
}

#[test]
#[ignore = "long-running ECDSA proving — run with --test-threads=1"]
fn p7s_v12_round_trip() {
    let circuit_bytes = load_circuit_bytes();
    let (prover, verifier) = build_prover_and_verifier(&circuit_bytes);

    // 1. Prove.
    let proof_bytes = prover
        .prove(WITNESS_BLOB, PUBLIC_BLOB)
        .expect("prover succeeded");
    assert!(!proof_bytes.is_empty(), "proof bytes non-empty");
    // Schema version u32 LE prefix is the first 4 bytes.
    assert_eq!(proof_bytes[0], 12, "schema version u32 byte 0 = 12");
    assert_eq!(proof_bytes[1], 0, "schema version u32 byte 1 = 0");

    // 2. Verify.
    let extracted = verifier
        .verify(PUBLIC_BLOB, &proof_bytes)
        .expect("verifier accepted proof");

    // 3. Cross-check public outputs against parsed public blob.
    let parsed = parse_public_blob(PUBLIC_BLOB).expect("parse public blob");
    assert_eq!(extracted.nullifier, parsed.nullifier, "nullifier match");
    assert_eq!(
        extracted.enroll_commit, parsed.enroll_commit,
        "enroll_commit match"
    );
    assert_eq!(
        extracted.enroll_nullifier, parsed.enroll_nullifier,
        "enroll_nullifier match"
    );
    assert_eq!(
        extracted.trust_anchor_index, parsed.trust_anchor_index,
        "trust_anchor_index match"
    );
}

#[test]
#[ignore = "long-running ECDSA proving — run with --test-threads=1"]
fn p7s_v12_corrupt_proof_rejected() {
    let circuit_bytes = load_circuit_bytes();
    let (prover, verifier) = build_prover_and_verifier(&circuit_bytes);

    let mut proof_bytes = prover.prove(WITNESS_BLOB, PUBLIC_BLOB).unwrap();
    // Flip a byte in the middle of the proof (past the schema version
    // prefix and past the 8 mac values that codec-decode-success-checks).
    let target = proof_bytes.len() / 2;
    proof_bytes[target] ^= 0xFF;

    let result = verifier.verify(PUBLIC_BLOB, &proof_bytes);
    assert!(result.is_err(), "corrupt proof must be rejected");
}

#[test]
fn p7s_v12_round_trip_fixture_files_exist() {
    // Cheap sanity that fixture pieces are present and non-empty.
    assert!(!WITNESS_BLOB.is_empty(), "witness fixture present");
    assert!(!PUBLIC_BLOB.is_empty(), "public fixture present");
    assert!(!COMPRESSED_CIRCUIT.is_empty(), "circuit fixture present");
    let parsed = parse_public_blob(PUBLIC_BLOB).expect("public blob parses");
    assert_eq!(parsed.trust_anchor_index, 0, "TestAnchorA index = 0");
}

#[test]
fn p7s_v12_prover_constructor_decodes_circuit() {
    // Confirms the prover constructor is reachable end-to-end without
    // requiring a long-running proof. This catches regressions in
    // `P7sZkProver::new` (Ligero parameter optimization, circuit decode)
    // independent of the actual prove call.
    let circuit_bytes = load_circuit_bytes();
    let (prover, verifier) = build_prover_and_verifier(&circuit_bytes);

    use longfellow::p7s_zk::layout::{HASH_PUB_TOTAL, SIG_PUB_TOTAL};
    assert_eq!(
        prover.hash_circuit_num_public_inputs(),
        HASH_PUB_TOTAL,
        "hash circuit num_public_inputs from fixture"
    );
    assert_eq!(
        prover.signature_circuit_num_public_inputs(),
        SIG_PUB_TOTAL,
        "sig circuit num_public_inputs from fixture"
    );
    // Same constants on the verifier side.
    assert_eq!(
        verifier.hash_circuit_num_public_inputs(),
        HASH_PUB_TOTAL
    );
    assert_eq!(
        verifier.signature_circuit_num_public_inputs(),
        SIG_PUB_TOTAL
    );
}
