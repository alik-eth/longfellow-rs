use crate::{
    circuit::Circuit,
    fields::ProofFieldElement,
    ligero::{LigeroParameters, prover::LigeroProver},
    sumcheck::{ProverResult, SumcheckProtocol, initialize_transcript},
    transcript::{Transcript, TranscriptMode},
    witness::Witness,
    zk_one_circuit::proof::Proof,
};
use anyhow::anyhow;
use rand::RngCore;

/// Longfellow ZK prover.
pub struct Prover<'a, FE: ProofFieldElement> {
    sumcheck_prover: SumcheckProtocol<'a, FE>,
    ligero_prover: LigeroProver<FE>,
}

impl<'a, FE: ProofFieldElement> Prover<'a, FE> {
    /// Construct a new prover from a circuit and a choice of Ligero parameters.
    pub fn new(circuit: &'a Circuit<FE>, ligero_parameters: LigeroParameters) -> Self {
        let sumcheck_prover = SumcheckProtocol::new(circuit);
        let ligero_prover = LigeroProver::new(circuit, ligero_parameters);
        Self {
            sumcheck_prover,
            ligero_prover,
        }
    }

    /// Construct a proof for the given statement and witness.
    ///
    /// The `inputs` argument represents all inputs to the circuit defining the theorem being
    /// proven. This includes both the statement, or public inputs, and the witness, or private
    /// inputs. The definition of the circuit determines which inputs are which.
    pub fn prove(&self, session_id: &[u8], inputs: &[FE]) -> Result<Proof<FE>, anyhow::Error> {
        let circuit = self.sumcheck_prover.circuit();

        if inputs.len() != circuit.num_inputs() {
            return Err(anyhow!("input length does not match circuit"));
        }

        // Evaluate circuit.
        let evaluation = circuit.evaluate(inputs)?;

        // Select one-time-pad, and combine with circuit witness into the Ligero witness.
        let mut rng = rand::rng();
        let mut buffer = vec![0; FE::num_bytes()];
        let witness = Witness::fill_witness(
            self.ligero_prover.witness_layout().clone(),
            evaluation.private_inputs(circuit.num_public_inputs()),
            || FE::sample_from_source(&mut buffer, |bytes| rng.fill_bytes(bytes)),
        );

        // Construct Ligero commitment.
        let commitment_state = self.ligero_prover.commit(&witness)?;

        // Start of Fiat-Shamir transcript.
        let mut transcript = Transcript::new(session_id, TranscriptMode::V3Compatibility).unwrap();
        transcript.write_byte_array(commitment_state.commitment().as_bytes())?;
        initialize_transcript(
            &mut transcript,
            circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
        )?;

        // Sumcheck: generate proof and linear constraints.
        let ProverResult {
            proof: sumcheck_proof,
            linear_constraints,
        } = self
            .sumcheck_prover
            .prove(&evaluation, &mut transcript, &witness)?;

        // Generate Ligero proof.
        let ligero_proof =
            self.ligero_prover
                .prove(&mut transcript, &commitment_state, &linear_constraints)?;

        Ok(Proof {
            oracle: session_id.to_vec(),
            sumcheck_proof,
            ligero_commitment: *commitment_state.commitment(),
            ligero_proof,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ParameterizedCodec,
        test_vector::load_rfc,
        zk_one_circuit::{prover::Prover, verifier::Verifier},
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test(unsupported = test)]
    fn proof_round_trip() {
        let (test_vector, circuit) = load_rfc();
        let session_id = b"testtesttesttesttesttesttesttest";

        let prover = Prover::new(&circuit, *test_vector.ligero_parameters());
        let proof = prover
            .prove(session_id, test_vector.valid_inputs())
            .unwrap();
        assert_eq!(session_id, proof.oracle());

        proof.roundtrip(&Verifier::new(&circuit, *test_vector.ligero_parameters()));
    }
}
