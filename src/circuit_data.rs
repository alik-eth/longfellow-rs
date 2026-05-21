//! Pre-compiled circuit-bytes asset surface.
//!
//! Single source of truth for the p7s circuit binary across all
//! consumers. The bytes were captured by the C++ vendor's
//! `p7s_dump_circuits` extern-C entry (Task #95 work-item 0); the
//! committed file is `crates/longfellow/circuits/p7s_circuit_v12.bin.zst`
//! (511 KB compressed, raw sha256 `00278352...624d`). As of v13
//! (Task #37 — variable-length serialNumber) the asset is the v13
//! circuit; the `_v12` filename/symbol names are retained to avoid
//! churn across consumers.
//!
//! Phase 2 redirects (#78-#82) consume this asset instead of relying on
//! `longfellow-sys`'s C++ static-data lookup. Phase 3 deletes the FFI
//! crate entirely; this module then becomes the only path for circuit
//! bytes.

use alloc::vec::Vec;

/// Decompress a zstd blob via the pure-Rust `ruzstd` decoder.
///
/// `ruzstd` replaces the C-backed `zstd` crate so the `prover` feature
/// compiles for `wasm32-unknown-unknown` (and other targets without a C
/// toolchain). Decode-only — the prover never compresses.
#[cfg(feature = "prover")]
fn zstd_decode(compressed: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut decoder = ruzstd::streaming_decoder::StreamingDecoder::new(compressed)
        .expect("circuit fixture is a valid zstd stream");
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("circuit fixture decompresses");
    decompressed
}

/// Raw zstd-compressed bytes of the v12 p7s circuit binary.
///
/// Layout: `Circuit::<Field2_128>` + `Circuit::<FieldP256>` back-to-back,
/// per `crates/longfellow/src/p7s_zk/prover.rs::P7sZkProver::new`.
pub static P7S_CIRCUIT_V12_ZST: &[u8] =
    include_bytes!("../circuits/p7s_circuit_v12.bin.zst");

/// Decompress and cache the v12 p7s circuit bytes.
///
/// First call pays the zstd decode (~1-5 ms typical); subsequent calls
/// return the cached `Vec<u8>` reference. Cached for the process
/// lifetime via `OnceLock`.
///
/// Gated to `feature = "prover"` because `zstd` itself is prover-only.
/// Verifier-only consumers carry their own decompression path or
/// receive raw bytes from the host.
#[cfg(feature = "prover")]
pub fn p7s_circuit_v12_decompressed() -> &'static [u8] {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE
        .get_or_init(|| zstd_decode(P7S_CIRCUIT_V12_ZST))
        .as_slice()
}

/// Raw zstd-compressed bytes of the v12 mdoc circuit binary.
///
/// Layout: `Circuit::<FieldP256>` (signature) + `Circuit::<Field2_128>`
/// (hash) back-to-back, as serialized by the C++ vendor's
/// `generate_circuit` and decoded by
/// [`crate::mdoc_zk::common_initialization`] (Task #3 item 2). The
/// committed file is `crates/longfellow/circuits/mdoc_circuit_v12.bin.zst`
/// (349 KB compressed, 118 MB raw, raw sha256 `568cf594...6dd4`); the v12
/// hash circuit has `npub = 2296` (696 ISRG baseline + 1600 v12 wires).
pub static MDOC_CIRCUIT_V12_ZST: &[u8] =
    include_bytes!("../circuits/mdoc_circuit_v12.bin.zst");

/// Decompress and cache the v12 mdoc circuit bytes.
///
/// First call pays the zstd decode; subsequent calls return the cached
/// `Vec<u8>` reference. Cached for the process lifetime via `OnceLock`.
///
/// Gated to `feature = "prover"` because `zstd` itself is prover-only.
/// Verifier-only (`--features verifier --no-default-features`) consumers
/// receive the raw decompressed bytes from the host (the SP1 wrapper) and
/// pass them straight to [`crate::mdoc_zk::verify_v12_with_circuit`].
#[cfg(feature = "prover")]
pub fn mdoc_circuit_v12_decompressed() -> &'static [u8] {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE
        .get_or_init(|| zstd_decode(MDOC_CIRCUIT_V12_ZST))
        .as_slice()
}
