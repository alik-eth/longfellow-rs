//! Integration test for Task #95 work-item 0: round-trip decode of the
//! committed p7s circuit fixture.
//!
//! The fixture `circuits/p7s_circuit_v12.bin.zst` is
//! produced by the `dump-p7s-circuits` binary in `crates/longfellow-sys`
//! after the C++ vendor's `p7s_dump_circuits` extern-C entry runs
//! `CircuitRep<F>::to_bytes` on the static `get_hash_circuit()` /
//! `get_sig_circuit()`. This test loads the compressed bytes,
//! decompresses them, and round-trips through `Circuit::<F>::decode`
//! to confirm:
//!   * The committed bytes parse cleanly under both field types.
//!   * The decoded circuits' `npub_in` matches the C++ static_assert
//!     constants from `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc`
//!     (kHashPubTotal = 1842, kSigPubTotal = 1154).
//!   * No trailing bytes after both circuits parse.
//!
//! Run with `cargo test -p longfellow --test p7s_zk_circuit_decode`.

use longfellow::{
    Codec,
    circuit::Circuit,
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    io::Cursor,
    p7s_zk::layout::{HASH_PUB_TOTAL, SIG_PUB_TOTAL},
};

// Public crate asset (sub-PR `circuit_data` in #78). Same compressed bytes
// the runtime stateless wrappers use, exercised here as a structural-decode
// regression guard.
use longfellow::circuit_data::P7S_CIRCUIT_V12_ZST;

fn load_decompressed_circuit_bytes() -> Vec<u8> {
    zstd::decode_all(P7S_CIRCUIT_V12_ZST).expect("zstd decode of p7s circuit fixture")
}

#[test]
fn p7s_circuit_fixture_decodes_under_both_fields() {
    let bytes = load_decompressed_circuit_bytes();
    let mut cursor = Cursor::new(bytes.as_slice());

    let hash_circuit = Circuit::<Field2_128>::decode(&mut cursor)
        .expect("p7s hash circuit decodes from fixture");
    let sig_circuit = Circuit::<FieldP256>::decode(&mut cursor)
        .expect("p7s sig circuit decodes from fixture");

    // No trailing bytes — same invariant `P7sZkProver::new` enforces.
    assert_eq!(
        cursor.position() as usize,
        bytes.len(),
        "expected end-of-buffer after both circuits decode"
    );

    // The C++ static_asserts pin these (p7s_zk.cc:489 + 562).
    assert_eq!(
        hash_circuit.num_public_inputs(),
        HASH_PUB_TOTAL,
        "hash circuit npub_in must equal kHashPubTotal = {HASH_PUB_TOTAL}"
    );
    assert_eq!(
        sig_circuit.num_public_inputs(),
        SIG_PUB_TOTAL,
        "sig circuit npub_in must equal kSigPubTotal = {SIG_PUB_TOTAL}"
    );
}
