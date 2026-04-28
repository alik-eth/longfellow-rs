//! Stateless v12 prove/verify wrappers.
//!
//! Stateless analog of the C++ `p7s_prove` / `p7s_verify` FFI surface
//! Phase 1 consumers used (via `longfellow_sys::p7s::*`). Both wrappers
//! lazy-init a process-wide `P7sZkProver` / `P7sZkVerifier` from the
//! committed circuit asset at
//! [`crate::circuit_data::P7S_CIRCUIT_V12_ZST`], so callers don't have
//! to thread circuit bytes / Ligero parameters through their own state.
//!
//! Phase 2 consumer-redirect crates (#78-#82) call these instead of the
//! FFI; Phase 3 then deletes `crates/longfellow-sys/` outright.

use crate::{
    Codec,
    circuit::Circuit,
    circuit_data::p7s_circuit_v12_decompressed,
    fields::{CodecFieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    io::Cursor,
    p7s_zk::{
        P7S_NREQ, P7S_RATE_INV, P7sV12PublicOutputs, P7sZkProver, P7sZkVerifier,
        default_ligero_params_for_circuit,
    },
};
use alloc::vec::Vec;
use anyhow::{Context, anyhow};
use std::sync::OnceLock;

/// Construct or return the cached `P7sZkProver`.
fn prover() -> Result<&'static P7sZkProver, anyhow::Error> {
    static CACHE: OnceLock<P7sZkProver> = OnceLock::new();
    if let Some(p) = CACHE.get() {
        return Ok(p);
    }
    let circuit_bytes = p7s_circuit_v12_decompressed();
    let (hash_params, sig_params) = derive_default_params(circuit_bytes)?;
    let prover = P7sZkProver::new(circuit_bytes, hash_params, sig_params)
        .context("p7s prove_v12: P7sZkProver::new failed")?;
    Ok(CACHE.get_or_init(|| prover))
}

/// Construct or return the cached `P7sZkVerifier`.
fn verifier() -> Result<&'static P7sZkVerifier, anyhow::Error> {
    static CACHE: OnceLock<P7sZkVerifier> = OnceLock::new();
    if let Some(v) = CACHE.get() {
        return Ok(v);
    }
    let circuit_bytes = p7s_circuit_v12_decompressed();
    let (hash_params, sig_params) = derive_default_params(circuit_bytes)?;
    let verifier = P7sZkVerifier::new(circuit_bytes, hash_params, sig_params)
        .context("p7s verify_v12: P7sZkVerifier::new failed")?;
    Ok(CACHE.get_or_init(|| verifier))
}

/// Decode the back-to-back hash + sig circuits and derive default Ligero
/// parameters. Done once per process and cached above.
fn derive_default_params(
    circuit_bytes: &[u8],
) -> Result<
    (
        crate::ligero::LigeroParameters,
        crate::ligero::LigeroParameters,
    ),
    anyhow::Error,
> {
    let mut cursor = Cursor::new(circuit_bytes);
    let hash_circuit = Circuit::<Field2_128>::decode(&mut cursor)
        .context("p7s stateless: hash circuit decode")?;
    let sig_circuit = Circuit::<FieldP256>::decode(&mut cursor)
        .context("p7s stateless: sig circuit decode")?;
    if cursor.position() as usize != circuit_bytes.len() {
        return Err(anyhow!(
            "p7s stateless: trailing bytes after both circuits decode"
        ));
    }
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
    Ok((hash_params, sig_params))
}

/// Stateless v12 prove. Mirrors the FFI surface
/// `longfellow_sys::p7s::prove(witness_blob, public_blob) -> P7sProof`.
///
/// Loads (cached) circuit bytes from
/// [`crate::circuit_data::P7S_CIRCUIT_V12_ZST`]. First call pays the
/// zstd decode + circuit decode + Ligero parameter derivation
/// (~few-hundred-ms total cold start); subsequent calls reuse the cache.
pub fn prove_v12(
    witness_blob: &[u8],
    public_blob: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    prover()?.prove(witness_blob, public_blob)
}

/// Stateless v12 verify. Mirrors the FFI surface
/// `longfellow_sys::p7s::verify(public_blob, proof) -> Result<(), _>`.
///
/// Returns the extracted public outputs on success. Cold-start cost
/// matches `prove_v12` above.
pub fn verify_v12(
    public_blob: &[u8],
    proof: &[u8],
) -> Result<P7sV12PublicOutputs, anyhow::Error> {
    verifier()?.verify(public_blob, proof)
}
