//! ECDSA witness reach-through into `mdoc_zk::ec`.
//!
//! Mirrors the C++ pattern at `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:2647-2651`:
//! call `VerifyWitness3<P256, Fp256Scalar>::compute_witness(qx, qy, e, r, s)`
//! then `fill_witness(filler)` to populate the per-circuit ECDSA witness wires.
//!
//! The Rust mdoc_zk port has the equivalent at
//! `crates/longfellow/src/mdoc_zk/ec.rs::fill_ecdsa_witness`, which writes
//! into a `&mut EcdsaWitness<'a>` typed view over a fixed-size
//! `[FieldP256; EcdsaWitness::LENGTH]` slice.
//!
//! This module provides a `compute_ecdsa_witness_wires(...)` adapter that
//! returns a flat `Vec<FieldP256>` of length `EcdsaWitness::LENGTH = 1034`
//! suitable for `Vec::extend_from_slice` into the sig dense array.

use crate::{
    Sha256Digest,
    fields::{FieldElement, fieldp256::FieldP256, fieldp256_scalar::FieldP256Scalar},
    mdoc_zk::{
        ec::{AffinePoint, Signature, fill_ecdsa_witness},
        layout::EcdsaWitness,
    },
};
use alloc::vec::Vec;
use anyhow::{Context, anyhow};

/// 32-byte big-endian ECDSA scalar length.
pub(crate) const ECDSA_SCALAR_BYTES: usize = 32;

/// Convert a 32-byte BE buffer into a `FieldP256Scalar`.
///
/// `FieldP256Scalar::try_from` expects little-endian; this helper handles the
/// BE→LE byte reversal that C++ p7s passes (cert_sig_r/s arrive in BE).
fn scalar_from_be(be: &[u8; ECDSA_SCALAR_BYTES]) -> Result<FieldP256Scalar, anyhow::Error> {
    let mut le = [0u8; ECDSA_SCALAR_BYTES];
    for i in 0..ECDSA_SCALAR_BYTES {
        le[i] = be[ECDSA_SCALAR_BYTES - 1 - i];
    }
    FieldP256Scalar::try_from(&le).map_err(|_| anyhow!("ECDSA scalar out of field range"))
}

/// Compute the ECDSA witness wires for a single signature against a known
/// public key + claimed digest.
///
/// Returns a `Vec<FieldP256>` of length `EcdsaWitness::LENGTH = 1034` ready to
/// be `extend_from_slice`'d into the sig dense array.
///
/// `pk_x`, `pk_y` — `FieldP256` (Montgomery domain) coordinates of the
/// public key. For the cert ECDSA, these come from
/// [`crate::p7s_zk::trust_anchors::trust_anchor_pk`]; for the content ECDSA,
/// from extracting the SPKI X/Y window of cert_tbs.
///
/// `digest_be` — 32-byte BE SHA-256 digest. ECDSA `bits2int` rule reads BE
/// → integer mod n; both `mdoc_zk::ec::fill_ecdsa_witness` and C++
/// `nat_from_be` honor this convention.
///
/// `sig_r_be`, `sig_s_be` — 32-byte BE ECDSA signature scalars.
pub(crate) fn compute_ecdsa_witness_wires(
    pk_x: FieldP256,
    pk_y: FieldP256,
    digest_be: &[u8; 32],
    sig_r_be: &[u8; ECDSA_SCALAR_BYTES],
    sig_s_be: &[u8; ECDSA_SCALAR_BYTES],
) -> Result<Vec<FieldP256>, anyhow::Error> {
    let pubkey = AffinePoint::new(pk_x, pk_y);
    let r = scalar_from_be(sig_r_be).context("invalid ECDSA r scalar")?;
    let s = scalar_from_be(sig_s_be).context("invalid ECDSA s scalar")?;
    let sig = Signature { r, s };
    let hash = Sha256Digest(*digest_be);

    let mut buffer = [FieldP256::ZERO; EcdsaWitness::LENGTH];
    {
        let mut witness = EcdsaWitness::new(&mut buffer);
        fill_ecdsa_witness(&mut witness, pubkey, sig, hash)
            .context("ECDSA witness population failed")?;
    }
    Ok(buffer.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_witness_length_is_1034() {
        assert_eq!(EcdsaWitness::LENGTH, 1034);
    }

    #[test]
    fn scalar_from_be_round_trip_zero() {
        let be = [0u8; 32];
        let scalar = scalar_from_be(&be).unwrap();
        assert_eq!(scalar, FieldP256Scalar::ZERO);
    }
}
