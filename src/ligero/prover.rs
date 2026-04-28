//! Ligero prover, specified in [Section 4.4][1].
//!
//! [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4

use crate::{
    circuit::Circuit,
    fields::ProofFieldElement,
    ligero::{
        LigeroChallenges, LigeroParameters,
        merkle::{MerkleTree, Root},
        proof::{LigeroProof, inner_product_vector},
        tableau::{Tableau, TableauLayout},
        write_hash_of_a, write_proof,
    },
    sumcheck::constraints::{LinearConstraints, QuadraticConstraint, quadratic_constraints},
    transcript::Transcript,
    witness::{Witness, WitnessLayout},
};

/// Prover for the Ligero ZK proof system.
#[derive(Debug, Clone)]
pub struct LigeroProver<FE: ProofFieldElement> {
    parameters: LigeroParameters,
    witness_layout: WitnessLayout,
    quadratic_constraints: Vec<QuadraticConstraint>,
    extend_context_block_ncol: FE::ExtendContext,
    extend_context_dblock_ncol: FE::ExtendContext,
    extend_context_block_dblock: FE::ExtendContext,
}

impl<FE: ProofFieldElement> LigeroProver<FE> {
    /// Construct a new prover for a circuit and set of parameter choices.
    pub fn new(circuit: &Circuit<FE>, ligero_parameters: LigeroParameters) -> Self {
        let witness_layout = WitnessLayout::from_circuit(circuit);
        let quadratic_constraints = quadratic_constraints(circuit, &witness_layout);
        let tableau_layout = TableauLayout::new(
            ligero_parameters,
            witness_layout.length(),
            quadratic_constraints.len(),
        );
        let extend_context_block_ncol =
            FE::extend_precompute(tableau_layout.block_size(), tableau_layout.num_columns());
        let extend_context_dblock_ncol =
            FE::extend_precompute(tableau_layout.dblock(), tableau_layout.num_columns());
        let extend_context_block_dblock =
            FE::extend_precompute(tableau_layout.block_size(), tableau_layout.dblock());

        Self {
            parameters: ligero_parameters,
            witness_layout,
            quadratic_constraints,
            extend_context_block_ncol,
            extend_context_dblock_ncol,
            extend_context_block_dblock,
        }
    }

    /// Commit to a Ligero witness, returning the full tableau and Merkle tree.
    pub fn commit(
        &self,
        witness: &Witness<FE>,
    ) -> Result<LigeroCommitmentState<FE>, anyhow::Error> {
        let tableau = Tableau::build(
            self.parameters,
            witness,
            &self.quadratic_constraints,
            &self.extend_context_block_ncol,
            &self.extend_context_dblock_ncol,
        );
        let merkle_tree = tableau.commit()?;
        let root = merkle_tree.root();

        Ok(LigeroCommitmentState {
            tableau,
            merkle_tree,
            root,
        })
    }

    /// Prove that the commitment satisfies the provided constraints. The provided transcript should
    /// have been used in [`crate::sumcheck::SumcheckProtocol::prove`] (or, equivalently,
    /// [`crate::sumcheck::SumcheckProtocol::linear_constraints`]).
    ///
    /// This is specified in [4.4][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-4.4
    pub fn prove(
        &self,
        transcript: &mut Transcript,
        commitment_state: &LigeroCommitmentState<FE>,
        linear_constraints: &LinearConstraints<FE>,
    ) -> Result<LigeroProof<FE>, anyhow::Error> {
        let tableau = commitment_state.tableau();
        let merkle_tree = commitment_state.merkle_tree();

        write_hash_of_a(transcript)?;

        let challenges = LigeroChallenges::generate(
            transcript,
            tableau.layout(),
            linear_constraints.len(),
            self.quadratic_constraints.len(),
        )?;

        // Sum blinded witness rows into the low degree test
        let mut low_degree_test_proof = tableau.contents()[TableauLayout::low_degree_test_row()]
            [0..tableau.layout().block_size()]
            .to_vec();
        for (witness_row, blind) in tableau
            .contents()
            .iter()
            .skip(tableau.layout().first_witness_row())
            .zip(challenges.low_degree_test_blind)
        {
            for (ldt_column, witness_column) in
                low_degree_test_proof.iter_mut().zip(witness_row.iter())
            {
                *ldt_column += blind * witness_column;
            }
        }

        // Sum random linear combinations of linear constraints into the dot proof
        let inner_product_vector = inner_product_vector(
            tableau.layout(),
            linear_constraints,
            &challenges.linear_constraint_alphas,
            &self.quadratic_constraints,
            &challenges.quadratic_constraint_alphas,
        )?;

        let mut dot_proof = tableau.contents()[TableauLayout::dot_proof_row()]
            [0..tableau.layout().dblock()]
            .to_vec();
        let mut inner_product_vector_extended = Vec::with_capacity(tableau.layout().block_size());
        for (witnesses, tableau_row) in inner_product_vector
            .chunks(tableau.layout().witnesses_per_row())
            .zip(
                tableau
                    .contents()
                    .iter()
                    .skip(tableau.layout().first_witness_row()),
            )
        {
            inner_product_vector_extended.truncate(0);
            inner_product_vector_extended
                .resize(tableau.layout().num_requested_columns(), FE::ZERO);
            inner_product_vector_extended.extend(witnesses);
            // Specification interpretation verification: nreq + the witnesses should be block size
            assert_eq!(
                inner_product_vector_extended.len(),
                tableau.layout().block_size()
            );

            for ((dot_proof_element, inner_product_element), tableau_element) in dot_proof
                .iter_mut()
                .zip(FE::extend(
                    &inner_product_vector_extended,
                    &self.extend_context_block_dblock,
                ))
                .zip(tableau_row.iter().take(tableau.layout().dblock()))
            {
                *dot_proof_element += inner_product_element * tableau_element;
            }
        }

        // Check that nothing grew the dot proof behind our back
        assert_eq!(dot_proof.len(), tableau.layout().dblock());

        let mut quadratic_proof = tableau.contents()[TableauLayout::quadratic_test_row()]
            [0..tableau.layout().dblock()]
            .to_vec();

        let first_x_row = tableau.layout().first_quadratic_constraint_row();
        let first_y_row = first_x_row + tableau.layout().num_quadratic_triples();
        let first_z_row = first_y_row + tableau.layout().num_quadratic_triples();

        for (index, challenge) in challenges.quadratic_proof_blind.into_iter().enumerate() {
            let x_row = &tableau.contents()[first_x_row + index];
            let y_row = &tableau.contents()[first_y_row + index];
            let z_row = &tableau.contents()[first_z_row + index];

            // quadratic_proof += uquad[i] * (z[i] - x[i] * y[i])
            for (((proof_element, x), y), z) in
                quadratic_proof.iter_mut().zip(x_row).zip(y_row).zip(z_row)
            {
                *proof_element += challenge * (*z - *x * y);
            }
        }

        // Specification interpretation verification: the middle part of the quadratic proof should
        // be all zeroes.
        assert_eq!(
            &quadratic_proof
                [tableau.layout().num_requested_columns()..tableau.layout().block_size()],
            vec![
                FE::ZERO;
                tableau.layout().block_size() - tableau.layout().num_requested_columns()
            ]
            .as_slice(),
        );

        // Quadratic proof consists of the nonzero parts of the proof
        let quadratic_proof_low = &quadratic_proof[0..tableau.layout().num_requested_columns()];
        let quadratic_proof_high = &quadratic_proof[tableau.layout().block_size()..];

        // Write proofs to the transcript
        write_proof(
            transcript,
            &low_degree_test_proof,
            &dot_proof,
            quadratic_proof_low,
            quadratic_proof_high,
        )?;

        let requested_column_indices = transcript.generate_naturals_without_replacement(
            tableau.layout().num_columns() - tableau.layout().dblock(),
            tableau.layout().num_requested_columns(),
        );

        // The specification for requested_columns suggests we should construct a table of
        // num_requested_columns rows and num_rows columns, whose rows consist of the tableau
        // columns at requested_column_indices, but longfellow-zk doesn't transpose, and we match
        // their behavior.
        // See compute_req in lib/ligero/ligero_prover.h.
        let mut requested_tableau_columns =
            vec![FE::ZERO; tableau.layout().num_requested_columns() * tableau.layout().num_rows()];

        for row in 0..tableau.layout().num_rows() {
            for (column, requested_column_index) in requested_column_indices.iter().enumerate() {
                requested_tableau_columns
                    [row * tableau.layout().num_requested_columns() + column] =
                    // Offset by dblock so we send tableau values and not witnesses. We send few
                    // enough columns that the verifier can't interpolate the polynomial and
                    // recompute witnesses.
                    tableau.contents()[row][*requested_column_index + tableau.layout().dblock()];
            }
        }

        let tableau_columns = requested_tableau_columns
            .chunks(tableau.layout().num_requested_columns())
            .map(|c| c.to_vec())
            .collect();

        // Gather nonces for requested columns.
        let merkle_tree_nonces = requested_column_indices
            .iter()
            .map(|index| merkle_tree.nonces()[*index])
            .collect();

        let inclusion_proof = merkle_tree.prove(requested_column_indices.as_slice());

        Ok(LigeroProof {
            low_degree_test_proof,
            dot_proof,
            quadratic_proof: (quadratic_proof_low.to_vec(), quadratic_proof_high.to_vec()),
            tableau_columns,
            inclusion_proof,
            merkle_tree_nonces,
        })
    }

    /// Returns the layout of the Ligero witness.
    pub fn witness_layout(&self) -> &WitnessLayout {
        &self.witness_layout
    }
}

/// Private state for the Ligero commitment scheme.
pub struct LigeroCommitmentState<FE> {
    tableau: Tableau<FE>,
    merkle_tree: MerkleTree,
    root: Root,
}

impl<FE> LigeroCommitmentState<FE> {
    /// Returns the tableau.
    pub fn tableau(&self) -> &Tableau<FE> {
        &self.tableau
    }

    /// Returns the Merkle tree committing to the tableau.
    pub fn merkle_tree(&self) -> &MerkleTree {
        &self.merkle_tree
    }

    /// Returns the commitment, the root of the Merkle tree.
    pub fn commitment(&self) -> &Root {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ParameterizedCodec,
        circuit::{Circuit, Evaluation},
        fields::{field2_128::Field2_128, fieldp128::FieldP128},
        ligero::Nonce,
        sumcheck::{SumcheckProtocol, constraints::quadratic_constraints, initialize_transcript},
        test_vector::{CircuitTestVector, load_mac, load_rfc},
        transcript::{Transcript, TranscriptMode},
        witness::{Witness, WitnessLayout},
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    fn prove<FE: ProofFieldElement>(test_vector: CircuitTestVector<FE>, circuit: Circuit<FE>) {
        let evaluation: Evaluation<FE> = circuit.evaluate(test_vector.valid_inputs()).unwrap();

        let witness = Witness::fill_witness(
            WitnessLayout::from_circuit(&circuit),
            evaluation.private_inputs(circuit.num_public_inputs()),
            || test_vector.pad(),
        );

        let ligero_prover = LigeroProver::new(&circuit, *test_vector.ligero_parameters());

        let tableau = Tableau::build_with_field_element_generator(
            *test_vector.ligero_parameters(),
            &witness,
            &ligero_prover.quadratic_constraints,
            || test_vector.pad(),
            &ligero_prover.extend_context_block_ncol,
            &ligero_prover.extend_context_dblock_ncol,
        );

        // Fix the nonce to match what longfellow-zk will do: all zeroes, but set the first byte to
        // what the fixed RNG yields.
        let mut merkle_tree_nonce = Nonce([0; 32]);
        merkle_tree_nonce.0[0] = test_vector.pad as u8;
        let merkle_tree = tableau
            .commit_with_merkle_tree_nonce_generator(|| merkle_tree_nonce)
            .unwrap();

        let ligero_commitment = merkle_tree.root();
        let commitment_state = LigeroCommitmentState {
            tableau,
            merkle_tree,
            root: ligero_commitment,
        };

        // Matches session used in longfellow-zk/lib/zk/zk_test.cc
        let mut transcript = Transcript::new(b"test", TranscriptMode::V3Compatibility).unwrap();
        transcript
            .write_byte_array(ligero_commitment.as_bytes())
            .unwrap();
        initialize_transcript(
            &mut transcript,
            &circuit,
            evaluation.public_inputs(circuit.num_public_inputs()),
        )
        .unwrap();

        let linear_constraints = SumcheckProtocol::new(&circuit)
            .linear_constraints(
                evaluation.public_inputs(circuit.num_public_inputs()),
                &mut transcript,
                &test_vector.sumcheck_proof(&circuit),
            )
            .unwrap();

        let ligero_proof = ligero_prover
            .prove(&mut transcript, &commitment_state, &linear_constraints)
            .unwrap();

        let encoded_ligero_proof = ligero_proof
            .get_encoded_with_param(commitment_state.tableau().layout())
            .unwrap();

        // It's not terribly useful to print 1000s of bytes of proof to stderr so we avoid the usual
        // assert_eq! form.
        assert!(test_vector.serialized_ligero_proof == encoded_ligero_proof);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_rfc_1_87474f308020535e57a778a82394a14106f8be5b() {
        let (test_vector, circuit) = load_rfc();
        prove::<FieldP128>(test_vector, circuit);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn longfellow_mac() {
        let (test_vector, circuit) = load_mac();
        prove::<Field2_128>(test_vector, circuit);
    }

    #[wasm_bindgen_test(unsupported = test)]
    fn ligero_proof_codec_roundtrip() {
        let (test_vector, circuit) = load_rfc();

        let witness_layout = WitnessLayout::from_circuit(&circuit);
        let quadratic_constraints = quadratic_constraints(&circuit, &witness_layout);
        let tableau_layout = TableauLayout::new(
            *test_vector.ligero_parameters(),
            witness_layout.length(),
            quadratic_constraints.len(),
        );

        let decoded = LigeroProof::<FieldP128>::get_decoded_with_param(
            &tableau_layout,
            &test_vector.serialized_ligero_proof,
        )
        .unwrap();
        let encoded = decoded.get_encoded_with_param(&tableau_layout).unwrap();

        assert_eq!(test_vector.serialized_ligero_proof, encoded);
    }
}
