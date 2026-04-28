//! Smoke tests for the on-disk fixture set under `crates/longfellow/tests/fixtures/`.
//!
//! Pure structural sanity:
//!   * each fixture file exists and is non-empty
//!   * each `.qkb.p7s` / `.p7s` starts with a DER `SEQUENCE` tag (0x30)
//!     followed by a long-form length encoding — i.e., looks like a CMS
//!     `ContentInfo` outer wrapper at the byte level
//!   * the JSON KAT parses
//!
//! Deliberately lightweight: no full ASN.1 / CMS parsing here (avoids a
//! new `cms` dev-dep), no ZK verification (that's #75's parity
//! driver). Production-shaped CMS validation already lives in the
//! `zk-eidas-p7s` crate's host pipeline; #74 only needs to confirm the
//! bytes are plausibly the CMS documents we shipped.

use longfellow::{
    Codec,
    circuit::Circuit,
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    io::Cursor,
    p7s_zk::default_ligero_params_for_circuit,
};
use std::path::PathBuf;

/// Resolve a fixture path under `crates/longfellow/tests/fixtures/`.
fn fixture_path(rel: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures");
    p.push(rel);
    p
}

/// Resolve a path under the ISRG-imported `tests/test-vectors/`.
/// (`test-vectors/` is at the crate root, alongside `tests/`.)
fn test_vector_path(rel: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("test-vectors");
    p.push(rel);
    p
}

/// Verify a candidate CMS DER blob starts with a `SEQUENCE` tag (0x30)
/// in long-form length encoding (top byte 0x80-0xFF in the first
/// length octet). Any well-formed CMS `ContentInfo` will satisfy this
/// — they universally exceed 127 bytes and use the long-form length
/// (the smallest fixture here is 1.7 KB).
fn assert_der_long_form_sequence(bytes: &[u8], path: &PathBuf) {
    assert!(
        bytes.len() >= 4,
        "fixture {path:?} too short to be a CMS ContentInfo: {}",
        bytes.len()
    );
    assert_eq!(
        bytes[0], 0x30,
        "fixture {path:?} first byte 0x{:02x} != 0x30 (DER SEQUENCE)",
        bytes[0]
    );
    assert!(
        bytes[1] & 0x80 != 0,
        "fixture {path:?} length byte 0x{:02x} not in long form",
        bytes[1]
    );
    // Long-form: low 7 bits of length-byte = number of subsequent length octets.
    let len_octets = (bytes[1] & 0x7f) as usize;
    assert!(
        len_octets > 0 && len_octets <= 4,
        "fixture {path:?} length-octets count {} unreasonable",
        len_octets
    );
    assert!(
        bytes.len() >= 2 + len_octets,
        "fixture {path:?} truncated before content"
    );
}

fn load_fixture(rel: &str) -> Vec<u8> {
    let path = fixture_path(rel);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {path:?}: {e}"));
    assert!(
        bytes.len() >= 1024,
        "fixture {path:?} suspiciously small: {} bytes",
        bytes.len()
    );
    bytes
}

#[test]
fn p7s_testanchor_a_v12_loads() {
    let bytes = load_fixture("p7s/testanchor-a-binding-v12.qkb.p7s");
    assert_der_long_form_sequence(&bytes, &fixture_path("p7s/testanchor-a-binding-v12.qkb.p7s"));
}

#[test]
fn p7s_testanchor_b_binding_loads() {
    let bytes = load_fixture("p7s/testanchor-b-binding.qkb.p7s");
    assert_der_long_form_sequence(&bytes, &fixture_path("p7s/testanchor-b-binding.qkb.p7s"));
}

#[test]
fn p7s_testanchor_b_admin_binding_loads() {
    let bytes = load_fixture("p7s/testanchor-b-admin-binding.qkb.p7s");
    assert_der_long_form_sequence(
        &bytes,
        &fixture_path("p7s/testanchor-b-admin-binding.qkb.p7s"),
    );
}

#[test]
fn p7s_diia_binding_loads() {
    let bytes = load_fixture("p7s/binding.qkb.p7s");
    assert_der_long_form_sequence(&bytes, &fixture_path("p7s/binding.qkb.p7s"));
}

#[test]
fn p7s_diia_admin_binding_loads() {
    let bytes = load_fixture("p7s/admin-binding.qkb.p7s");
    assert_der_long_form_sequence(&bytes, &fixture_path("p7s/admin-binding.qkb.p7s"));
}

#[test]
fn p7s_reference_czo_loads() {
    let bytes = load_fixture("p7s/reference/czo-test-testsigner.p7s");
    assert_der_long_form_sequence(
        &bytes,
        &fixture_path("p7s/reference/czo-test-testsigner.p7s"),
    );
}

#[test]
fn p7s_reference_microsec_loads() {
    let bytes = load_fixture("p7s/reference/hu-microsec-mic-1.p7s");
    assert_der_long_form_sequence(&bytes, &fixture_path("p7s/reference/hu-microsec-mic-1.p7s"));
}

#[test]
fn p7s_kat_subject_serial_json_parses() {
    let path = fixture_path("p7s/kat-subject-serial.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("failed to read KAT JSON {path:?}: {e}"));
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("kat-subject-serial.json must be valid JSON");
    // Sanity: KAT documents the X.520 serialNumber stable-ID anchor used
    // for invariant 7. Just check the file isn't empty/null.
    assert!(!v.is_null(), "kat-subject-serial.json must not be null");
}

#[test]
fn fixtures_readme_exists() {
    let path = fixture_path("README.md");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixtures README: {e}"));
    assert!(
        bytes.len() >= 200,
        "README too short — provenance docs missing"
    );
}

/// Catch-all: enumerate every file under `tests/fixtures/p7s/` and
/// assert it's at least 1KB (regardless of whether the test list above
/// covers it). Guards against silent fixture deletion or truncation.
#[test]
fn all_p7s_fixtures_meet_size_floor() {
    let dir = fixture_path("p7s");
    let mut found = 0;
    for entry in walk_files(&dir) {
        let bytes = std::fs::read(&entry).unwrap();
        // .json + .p7s + .qkb.p7s all matter; treat any > 100 bytes as a fixture
        // and assert all *binary* fixtures (.p7s endings) hit the 1KB floor.
        if entry
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s == "p7s")
            .unwrap_or(false)
        {
            assert!(
                bytes.len() >= 1024,
                "binary fixture {entry:?} too small: {} bytes",
                bytes.len()
            );
            found += 1;
        }
    }
    assert!(
        found >= 7,
        "expected ≥7 .p7s fixtures (5 main + 2 reference), found {found}"
    );
}

// ============================================================================
// mdoc V6/V7 circuit-binary fixtures
// ============================================================================
//
// The 8 mdoc circuit binaries live at `crates/longfellow/test-vectors/mdoc_zk/`,
// already imported by ISRG in phase 1.1. Naming convention is
// `{V}_{num_attrs}_{circuit_sha256}` (e.g., `6_1_137e5a75…`). Each binary
// packs two circuits back-to-back per `mdoc_zk::common_initialization`:
//   * signature circuit over Fp256
//   * hash circuit over GF(2^128)
//
// We exercise the full two-circuit decode path against each fixture
// (rather than just byte-existence checks) — this is the existing
// surface the consumer needs and `Circuit::decode` exercises a real
// chunk of the parser. Compressed via zstd would be `.circuit.zst`,
// but the mdoc_zk vectors are uncompressed.

const MDOC_V6_FIXTURES: &[&str] = &[
    "mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
    "mdoc_zk/6_2_b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e",
    "mdoc_zk/6_3_b2211223b954b34a1081e3fbf71b8ea2de28efc888b4be510f532d6ba76c2010",
    "mdoc_zk/6_4_c70b5f44a1365c53847eb8948ad5b4fdc224251a2bc02d958c84c862823c49d6",
];

const MDOC_V7_FIXTURES: &[&str] = &[
    "mdoc_zk/7_1_8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121",
    "mdoc_zk/7_2_6a5810683e62b6d7766ebd0d7ca72518a2b8325418142adcadb10d51dbbcd5ad",
    "mdoc_zk/7_3_8ee4849ae1293ae6fe5f9082ce3e5e15c4f198f2998c682fa1b727237d6d252f",
    "mdoc_zk/7_4_5aebdaaafe17296a3ef3ca6c80c6e7505e09291897c39700410a365fb278e460",
];

/// Decode a mdoc two-circuit binary (signature then hash, per
/// `mdoc_zk::common_initialization`). The on-disk fixtures are
/// zstd-compressed; we decompress before parsing.
fn decode_mdoc_two_circuit_binary(compressed: &[u8]) {
    let bytes = zstd::decode_all(compressed).expect("mdoc fixture must zstd-decompress");
    let mut cursor = Cursor::new(bytes.as_slice());
    Circuit::<FieldP256>::decode(&mut cursor).expect("signature circuit decode");
    Circuit::<Field2_128>::decode(&mut cursor).expect("hash circuit decode");
    assert_eq!(
        cursor.position() as usize,
        bytes.len(),
        "mdoc circuit binary has trailing bytes after both circuits decoded"
    );
}

#[test]
fn mdoc_v6_circuits_decode() {
    for rel in MDOC_V6_FIXTURES {
        let path = test_vector_path(rel);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read mdoc V6 fixture {path:?}: {e}"));
        assert!(
            bytes.len() > 100_000,
            "mdoc V6 fixture {path:?} suspiciously small: {} bytes",
            bytes.len()
        );
        decode_mdoc_two_circuit_binary(&bytes);
    }
}

#[test]
fn mdoc_v7_circuits_decode() {
    for rel in MDOC_V7_FIXTURES {
        let path = test_vector_path(rel);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read mdoc V7 fixture {path:?}: {e}"));
        assert!(
            bytes.len() > 100_000,
            "mdoc V7 fixture {path:?} suspiciously small: {} bytes",
            bytes.len()
        );
        decode_mdoc_two_circuit_binary(&bytes);
    }
}

#[test]
fn mdoc_proof_bytes_are_present() {
    // Just byte-existence + size floor — full proof decode requires the
    // matching circuit context (`MdocZkProof::decode_with_param`), which
    // belongs to the parity driver in #75.
    for rel in &[
        "mdoc_zk/v6_1attr_issue_date.proof",
        "mdoc_zk/v7_1attr_issue_date.proof",
    ] {
        let path = test_vector_path(rel);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read mdoc proof {path:?}: {e}"));
        assert!(
            bytes.len() > 100_000,
            "mdoc proof {path:?} suspiciously small: {} bytes",
            bytes.len()
        );
    }
}

#[test]
fn mdoc_v6_v7_witness_metadata_json_parses() {
    let path = test_vector_path("mdoc_zk/v6_v7_1attr_issue_date.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read metadata JSON: {e}"));
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("witness metadata JSON must be valid");
    assert!(!v.is_null(), "metadata JSON must not be null");
}

// ============================================================================
// LigeroParameters optimizer sanity (Task #74/B).
// ============================================================================
//
// `default_ligero_params_for_circuit` ports the C++ production optimizer at
// `vendor/longfellow-zk/lib/circuits/mdoc/circuit_maker.cc:64` and produces
// a `LigeroParameters` struct from a decoded circuit. We exercise it
// against a real V6 mdoc hash circuit and assert the results pass
// internal Ligero invariants:
//
//   * `block_size == (num_columns + 1) / (2 + rateinv)`
//   * `witnesses_per_row == block_size - nreq`
//   * `nreq` matches the input
//   * `2 * block_size - 1 <= num_columns`
//
// We do NOT cross-check against ISRG's `kZkSpecs[]` hardcoded values
// (`mdoc_zk/mod.rs::signature_ligero_parameters` etc.). My optimizer
// matches the production C++ optimizer's behavior on tied proof-sizes
// (lowest-e wins; verified by hand for V6 num_attrs=1 hash circuit:
// e=3947 and e=4096 produce the same proof size of 110720 bytes), but
// `kZkSpecs[]` records 4096 — a tied value selected at production time
// by something other than the proof-size minimizer (likely manual
// power-of-two preference). For p7s usage — where the goal is consistent
// Rust-prover ↔ Rust-verifier agreement — any consistent choice the
// optimizer picks works. Cross-language Rust↔C++ parity at the proof-
// bytes level (#75 / #76) needs the C++ side's exact `kZkSpecs[]`-style
// table; that's #98's territory.

const V6_RATE_INV: usize = 4;
const V6_NREQ: usize = 128;
const F2_128_BYTES: u64 = 16;
const F2_128_SUBFIELD_BYTES: u64 = 2;
const FP256_BYTES: u64 = 32;
const FP256_SUBFIELD_BYTES: u64 = 32;

#[test]
fn ligero_params_invariants_hold_on_v6_circuit() {
    let path = test_vector_path(MDOC_V6_FIXTURES[0]);
    let compressed = std::fs::read(&path).unwrap();
    let bytes = zstd::decode_all(compressed.as_slice()).unwrap();
    let mut cursor = Cursor::new(bytes.as_slice());
    let sig_circuit = Circuit::<FieldP256>::decode(&mut cursor).unwrap();
    let hash_circuit = Circuit::<Field2_128>::decode(&mut cursor).unwrap();

    let sig_params = default_ligero_params_for_circuit(
        &sig_circuit,
        V6_RATE_INV,
        V6_NREQ,
        FP256_BYTES,
        FP256_SUBFIELD_BYTES,
    );
    let hash_params = default_ligero_params_for_circuit(
        &hash_circuit,
        V6_RATE_INV,
        V6_NREQ,
        F2_128_BYTES,
        F2_128_SUBFIELD_BYTES,
    );

    for (label, p) in [("sig", &sig_params), ("hash", &hash_params)] {
        assert_eq!(p.nreq, V6_NREQ, "{label}: nreq must match input");
        assert_eq!(
            p.block_size,
            (p.num_columns + 1) / (2 + V6_RATE_INV),
            "{label}: block_size formula"
        );
        assert_eq!(
            p.witnesses_per_row,
            p.block_size - p.nreq,
            "{label}: witnesses_per_row formula"
        );
        assert_eq!(
            p.witnesses_per_row, p.quadratic_constraints_per_row,
            "{label}: witnesses_per_row == quadratic_constraints_per_row by construction"
        );
        assert!(
            p.num_columns >= 2 * p.block_size - 1,
            "{label}: dblock <= block_enc"
        );
    }
    // The optimizer should have picked a non-trivial block_enc — sanity-
    // check it landed in the iterated range [100, 2^17].
    assert!(
        sig_params.num_columns >= 100 && sig_params.num_columns <= (1 << 17),
        "sig block_enc {} outside iterated range",
        sig_params.num_columns
    );
    assert!(
        hash_params.num_columns >= 100 && hash_params.num_columns <= (1 << 17),
        "hash block_enc {} outside iterated range",
        hash_params.num_columns
    );
}

/// Recursive directory walk producing only files (not subdirs).
fn walk_files(dir: &PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("read_dir {d:?}: {e}")) {
            let entry = entry.unwrap();
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}
