//! The Longfellow ZK proof type and its codec implementations.
//!
//! Lives outside `prover.rs` so the verifier path can decode/encode proofs
//! without pulling in the prover module (which depends on `rand`).

use crate::{
    Codec, ParameterizedCodec,
    fields::{CodecFieldElement, ProofFieldElement},
    io::{Cursor, Write},
    ligero::{merkle::Root, proof::LigeroProof},
    sumcheck::SumcheckProof,
    zk_one_circuit::verifier::Verifier,
};
use alloc::vec::Vec;
use anyhow::anyhow;

/// Longfellow ZK proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<FE> {
    pub(super) oracle: Vec<u8>,
    pub(super) sumcheck_proof: SumcheckProof<FE>,
    pub(super) ligero_commitment: Root,
    pub(super) ligero_proof: LigeroProof<FE>,
}

impl<FE> Proof<FE> {
    /// Returns the byte string used to select a random oracle.
    pub fn oracle(&self) -> &[u8] {
        &self.oracle
    }

    /// Returns the Sumcheck component of the proof.
    pub fn sumcheck_proof(&self) -> &SumcheckProof<FE> {
        &self.sumcheck_proof
    }

    /// Returns the Ligero commitment.
    pub fn ligero_commitment(&self) -> Root {
        self.ligero_commitment
    }

    /// Returns the Ligero component of the proof.
    pub fn ligero_proof(&self) -> &LigeroProof<FE> {
        &self.ligero_proof
    }
}

impl<'a, F: CodecFieldElement + ProofFieldElement> ParameterizedCodec<Verifier<'a, F>>
    for Proof<F>
{
    /// Deserialize a Longfellow ZK proof.
    ///
    /// See section [7.5][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.5
    fn decode_with_param(
        verifier: &Verifier<F>,
        bytes: &mut Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let oracle = u8::decode_fixed_array(bytes, 32)?.to_vec();
        let ligero_commitment = Root::decode(bytes)?;
        let sumcheck_proof = SumcheckProof::<F>::decode_with_param(verifier.circuit, bytes)?;
        let ligero_proof = LigeroProof::<F>::decode_with_param(verifier.tableau_layout(), bytes)?;

        Ok(Self {
            oracle,
            sumcheck_proof,
            ligero_commitment,
            ligero_proof,
        })
    }

    /// Encode a Longfellow ZK proof.
    ///
    /// See section [7.5][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.5
    fn encode_with_param<W: Write>(
        &self,
        verifier: &Verifier<F>,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error> {
        let oracle: &[u8; 32] = self
            .oracle
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("oracle is not 32 bytes long"))?;
        u8::encode_fixed_array(oracle, bytes)?;
        self.ligero_commitment.encode(bytes)?;
        self.sumcheck_proof
            .encode_with_param(verifier.circuit, bytes)?;
        self.ligero_proof
            .encode_with_param(verifier.tableau_layout(), bytes)?;

        Ok(())
    }
}
