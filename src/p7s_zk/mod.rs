//! Rust consumer for the C++-compiled p7s ZK circuit.
//!
//! Mirrors the architecture of `mdoc_zk`: this module loads
//! pre-compiled circuit bytes (produced offline by the C++ circuit-
//! builder in `vendor/longfellow-zk/lib/circuits/p7s/`) and drives the
//! existing Sumcheck/Ligero proof system on them. It does NOT itself
//! construct circuits — that work stays in the C++ build-time tool per
//! the migration spec's option-(c) amendment (2026-04-28).
//!
//! ABI surface mirrors `crates/longfellow-sys/src/p7s.rs`'s
//! `prove(witness_blob, public_blob)` / `verify(public_blob, proof)`
//! pair — opaque byte buffers in, opaque proof bytes out — except the
//! Rust side also accepts the pre-compiled circuit binary as an
//! explicit argument (the C++ FFI links the circuit in via static
//! data; the Rust consumer loads from disk).
//!
//! v12 schema (the only schema the underlying C++ circuit currently
//! recognizes; v11 is a hard-fork distinguisher rejected at parse
//! time). Witness / public layouts are documented byte-for-byte in
//! `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc`'s "schema
//! history" comment block.
//!
//! Phase split:
//!   * #71 (this commit) — module skeleton: layout constants, parsed
//!     blob structs, module wiring. No parser, no prover/verifier
//!     implementations yet.
//!   * #95 — v12 plumbing: `parse_witness_blob`, `parse_public_blob`,
//!     `P7sZkProver` / `P7sZkVerifier` constructors that load circuit
//!     bytes, public-input wire-layout extraction (the
//!     `fill_hash_public_inputs` / `push_*` mirrors).

#[cfg(feature = "prover")]
pub(crate) mod ecdsa_witness;
#[cfg(feature = "prover")]
pub(crate) mod invariants;
pub mod layout;
pub mod mac;
#[cfg(feature = "prover")]
pub(crate) mod mac_witness;
pub mod params;
pub mod parser;
#[cfg(feature = "prover")]
pub(crate) mod preimages;
#[cfg(feature = "prover")]
pub mod prover;
pub mod public_inputs;
#[cfg(feature = "prover")]
pub(crate) mod sha256_witness;
#[cfg(feature = "prover")]
pub(crate) mod trust_anchors;
pub mod verifier;
pub mod witness;
#[cfg(feature = "prover")]
pub(crate) mod witness_fill;

pub use params::{P7S_NREQ, P7S_RATE_INV, default_ligero_params_for_circuit};
pub use parser::{parse_public_blob, parse_witness_blob};
#[cfg(feature = "prover")]
pub use prover::P7sZkProver;
pub use public_inputs::ParsedPublic;
pub use verifier::P7sZkVerifier;
pub use witness::ParsedWitness;
