//! Pre-compiled circuit-bytes asset surface.
//!
//! Single source of truth for the v12 p7s circuit binary across all
//! consumers. The bytes were captured by the C++ vendor's
//! `p7s_dump_circuits` extern-C entry (Task #95 work-item 0); the
//! committed file is `crates/longfellow/circuits/p7s_circuit_v12.bin.zst`
//! (508 KB compressed, raw sha256 `dbbb7b53...e2b4`).
//!
//! Phase 2 redirects (#78-#82) consume this asset instead of relying on
//! `longfellow-sys`'s C++ static-data lookup. Phase 3 deletes the FFI
//! crate entirely; this module then becomes the only path for circuit
//! bytes.

use alloc::vec::Vec;

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
        .get_or_init(|| {
            zstd::decode_all(P7S_CIRCUIT_V12_ZST)
                .expect("p7s v12 circuit fixture decompresses")
        })
        .as_slice()
}
