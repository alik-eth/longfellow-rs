//! Two-circuit proof for a p7s presentation.
//!
//! Mirrors `MdocZkProof` (`mdoc_zk/mod.rs:1000`) for the p7s schema. The proof
//! bytes carry:
//!   * 8 native MAC values (one `Field2_128` per bound message half)
//!   * hash-circuit Ligero commitment + Sumcheck proof + Ligero proof
//!   * sig-circuit Ligero commitment + Sumcheck proof + Ligero proof
//!
//! Wire format (matches C++ `p7s_zk.cc:2708-2725` schema, simplified for
//! Rust↔Rust scope A — no zstd, no CBOR; flat self-delimiting binary):
//!
//!   `[mac_values × 8] [hash_commitment] [hash_sumcheck] [hash_ligero]
//!    [sig_commitment]  [sig_sumcheck]   [sig_ligero]`
//!
//! The schema-version u32 of the proof blob is owned by the caller (prover
//! prepends it; verifier strips it before calling [`P7sZkProof::decode_with_param`]).
//! Each `_with_param`-encoded section needs a `ProofContext` with the matching
//! circuit + Ligero `TableauLayout`, identical to mdoc.

use crate::{
    Codec, ParameterizedCodec,
    circuit::Circuit,
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    io::{Cursor, Write},
    ligero::{merkle::Root, proof::LigeroProof, tableau::TableauLayout},
    p7s_zk::mac::TOTAL_MAC_VALUES,
    sumcheck::SumcheckProof,
};

/// Two-circuit proof for a p7s presentation.
#[derive(Debug, PartialEq, Eq)]
pub struct P7sZkProof {
    pub(crate) mac_values: [Field2_128; TOTAL_MAC_VALUES],
    pub(crate) hash_commitment: Root,
    pub(crate) hash_sumcheck_proof: SumcheckProof<Field2_128>,
    pub(crate) hash_ligero_proof: LigeroProof<Field2_128>,
    pub(crate) signature_commitment: Root,
    pub(crate) signature_sumcheck_proof: SumcheckProof<FieldP256>,
    pub(crate) signature_ligero_proof: LigeroProof<FieldP256>,
}

/// Encoding parameter for `P7sZkProof::encode_with_param` /
/// `decode_with_param`. Mirrors `mdoc_zk::ProofContext`.
pub struct P7sProofContext<'a> {
    pub(crate) hash_circuit: &'a Circuit<Field2_128>,
    pub(crate) signature_circuit: &'a Circuit<FieldP256>,
    pub(crate) hash_layout: &'a TableauLayout,
    pub(crate) signature_layout: &'a TableauLayout,
}

impl<'a> ParameterizedCodec<P7sProofContext<'a>> for P7sZkProof {
    fn decode_with_param(
        ctx: &P7sProofContext<'a>,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let mut mac_values = [Field2_128::default(); TOTAL_MAC_VALUES];
        for slot in mac_values.iter_mut() {
            *slot = Field2_128::decode(cursor)?;
        }
        let hash_commitment = Root::decode(cursor)?;
        let hash_sumcheck_proof = SumcheckProof::decode_with_param(ctx.hash_circuit, cursor)?;
        let hash_ligero_proof = LigeroProof::decode_with_param(ctx.hash_layout, cursor)?;
        let signature_commitment = Root::decode(cursor)?;
        let signature_sumcheck_proof =
            SumcheckProof::decode_with_param(ctx.signature_circuit, cursor)?;
        let signature_ligero_proof = LigeroProof::decode_with_param(ctx.signature_layout, cursor)?;
        Ok(Self {
            mac_values,
            hash_commitment,
            hash_sumcheck_proof,
            hash_ligero_proof,
            signature_commitment,
            signature_sumcheck_proof,
            signature_ligero_proof,
        })
    }

    fn encode_with_param<W: Write>(
        &self,
        ctx: &P7sProofContext<'a>,
        out: &mut W,
    ) -> Result<(), anyhow::Error> {
        for mac in &self.mac_values {
            mac.encode(out)?;
        }
        self.hash_commitment.encode(out)?;
        self.hash_sumcheck_proof
            .encode_with_param(ctx.hash_circuit, out)?;
        self.hash_ligero_proof
            .encode_with_param(ctx.hash_layout, out)?;
        self.signature_commitment.encode(out)?;
        self.signature_sumcheck_proof
            .encode_with_param(ctx.signature_circuit, out)?;
        self.signature_ligero_proof
            .encode_with_param(ctx.signature_layout, out)?;
        Ok(())
    }
}
