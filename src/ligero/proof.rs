//! Ligero proof type and shared inner-product-vector helper.
//!
//! Extracted from `prover.rs` so that the verifier path can reach these types without
//! pulling in the prover module (which depends on `rand`).

use crate::{
    Codec, ParameterizedCodec,
    fields::{CodecFieldElement, ProofFieldElement},
    ligero::{
        Nonce,
        merkle::InclusionProof,
        tableau::TableauLayout,
    },
    sumcheck::constraints::{
        LinearConstraintLhsTerm, LinearConstraints, QuadraticConstraint,
    },
};
use anyhow::{Context, anyhow};
use std::io::{self, Write};

const MAX_RUN_LENGTH: usize = 1 << 25;

pub fn inner_product_vector<FE: ProofFieldElement>(
    layout: &TableauLayout,
    linear_constraints: &LinearConstraints<FE>,
    linear_constraint_alphas: &[FE],
    quadratic_constraints: &[QuadraticConstraint],
    quadratic_constraint_alphas: &[FE],
) -> Result<Vec<FE>, anyhow::Error> {
    let mut inner_product_vector =
        vec![FE::ZERO; layout.witnesses_per_row() * layout.num_constraint_rows()];

    for LinearConstraintLhsTerm {
        constraint_number,
        witness_index,
        constant_factor,
    } in linear_constraints.left_hand_side_terms()
    {
        inner_product_vector[*witness_index] +=
            linear_constraint_alphas[*constraint_number] * constant_factor;
    }

    // Sum quadratic constraints into IDOT row. Quadratic constraints come after the linear
    // constraints in the inner product vector.
    let xs_start = layout.num_linear_constraint_rows() * layout.witnesses_per_row();
    let ys_start = xs_start + layout.num_quadratic_triples() * layout.witnesses_per_row();
    let zs_start = ys_start + layout.num_quadratic_triples() * layout.witnesses_per_row();

    for i in 0..layout.num_quadratic_triples() {
        for j in 0..layout.witnesses_per_row() {
            let index = j + i * layout.witnesses_per_row();
            if index >= quadratic_constraints.len() {
                break;
            }
            let QuadraticConstraint { x, y, z } = quadratic_constraints[index];
            let alpha_x = quadratic_constraint_alphas[index * 3];
            let alpha_y = quadratic_constraint_alphas[index * 3 + 1];
            let alpha_z = quadratic_constraint_alphas[index * 3 + 2];

            inner_product_vector[xs_start + index] += alpha_x;
            inner_product_vector[x] -= alpha_x;

            inner_product_vector[ys_start + index] += alpha_y;
            inner_product_vector[y] -= alpha_y;

            inner_product_vector[zs_start + index] += alpha_z;
            inner_product_vector[z] -= alpha_z;
        }
    }

    Ok(inner_product_vector)
}

/// A Ligero proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LigeroProof<FieldElement> {
    pub low_degree_test_proof: Vec<FieldElement>,
    pub dot_proof: Vec<FieldElement>,
    pub quadratic_proof: (Vec<FieldElement>, Vec<FieldElement>),
    pub merkle_tree_nonces: Vec<Nonce>,
    pub tableau_columns: Vec<Vec<FieldElement>>,
    pub inclusion_proof: InclusionProof,
}
impl<FE: CodecFieldElement> ParameterizedCodec<TableauLayout> for LigeroProof<FE> {
    /// Deserialization of a Ligero proof implied by `serialize_ligero_proof` in [7.4][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.4
    fn decode_with_param(
        layout: &TableauLayout,
        cursor: &mut io::Cursor<&[u8]>,
    ) -> Result<Self, anyhow::Error> {
        let low_degree_test_proof = FE::decode_fixed_array(cursor, layout.block_size())?;
        let dot_proof = FE::decode_fixed_array(cursor, layout.dblock())?;
        let quadratic_proof = (
            FE::decode_fixed_array(cursor, layout.num_requested_columns())?,
            FE::decode_fixed_array(cursor, layout.dblock() - layout.block_size())?,
        );

        let merkle_tree_nonces = Nonce::decode_fixed_array(cursor, layout.num_requested_columns())?;

        // Columns are serialized as one or more runs, each of which is a length-prefixed vector. A
        // run may contain field or subfield elements.
        let expected_column_elements = layout.num_rows() * layout.num_requested_columns();
        let mut column_elements = Vec::with_capacity(expected_column_elements);
        let mut subfield_run = false;
        while column_elements.len() < expected_column_elements {
            // Sizes are usually u24 in Longfellow, but in this case it happens to be u32. See
            // `write_size` and `read_size` in lib/zk/zk_proof.h.
            let run_length =
                usize::try_from(u32::decode(cursor)?).context("failed to convert u32 to usize")?;
            if run_length > MAX_RUN_LENGTH {
                return Err(anyhow!("run exceeds maximum run length"));
            }
            if run_length + column_elements.len() > expected_column_elements {
                return Err(anyhow!(
                    "too many column elements in serialized proof: {} > {}",
                    run_length + column_elements.len(),
                    expected_column_elements
                ));
            }
            let run = if subfield_run {
                FE::decode_fixed_array_in_subfield(cursor, run_length)
            } else {
                FE::decode_fixed_array(cursor, run_length)
            }?;
            column_elements.extend(run);
            subfield_run = !subfield_run;
        }
        if column_elements.len() != expected_column_elements {
            return Err(anyhow!(
                "unexpected number of column elements in serialized proof"
            ));
        }

        let tableau_columns = column_elements
            .chunks(layout.num_requested_columns())
            .map(|v| v.to_vec())
            .collect();

        let inclusion_proof = InclusionProof::decode(cursor)?;

        Ok(Self {
            low_degree_test_proof,
            dot_proof,
            quadratic_proof,
            merkle_tree_nonces,
            tableau_columns,
            inclusion_proof,
        })
    }

    /// Serialization of a Ligero proof implied by `serialize_ligero_proof` in [7.4][1].
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/draft-google-cfrg-libzk-01#section-7.4
    fn encode_with_param<W: Write>(
        &self,
        _: &TableauLayout,
        bytes: &mut W,
    ) -> Result<(), anyhow::Error> {
        FE::encode_fixed_array(&self.low_degree_test_proof, bytes)?;
        FE::encode_fixed_array(&self.dot_proof, bytes)?;
        FE::encode_fixed_array(&self.quadratic_proof.0, bytes)?;
        FE::encode_fixed_array(&self.quadratic_proof.1, bytes)?;
        Nonce::encode_fixed_array(&self.merkle_tree_nonces, bytes)?;

        let column_elements: Vec<_> = self.tableau_columns.iter().flat_map(|v| v.iter()).collect();
        let mut column_elements_written = 0;
        let mut is_subfield_run = false;
        while column_elements_written < column_elements.len() {
            // Seek to end of current run
            let mut run_length = 0;
            for element in &column_elements[column_elements_written..] {
                if run_length == MAX_RUN_LENGTH {
                    break;
                }
                if element.is_in_subfield() == is_subfield_run {
                    run_length += 1;
                }
            }

            u32::try_from(run_length)
                .context("run length too big for u32")?
                .encode(bytes)?;

            for element in
                &column_elements[column_elements_written..column_elements_written + run_length]
            {
                if is_subfield_run {
                    element.encode_in_subfield(bytes)?;
                } else {
                    element.encode(bytes)?;
                }
            }

            column_elements_written += run_length;
            is_subfield_run = !is_subfield_run;
        }

        self.inclusion_proof.encode(bytes)?;

        Ok(())
    }
}

impl<FE: CodecFieldElement> LigeroProof<FE> {
    /// Stitch the quadratic proof parts back together with the middle span of zeroes.
    pub fn quadratic_proof(&self, layout: &TableauLayout) -> Vec<FE> {
        let mut proof = Vec::with_capacity(layout.dblock());
        proof.extend(&self.quadratic_proof.0);
        proof.resize(layout.block_size(), FE::ZERO);
        proof.extend(&self.quadratic_proof.1);
        assert_eq!(proof.len(), layout.dblock());

        proof
    }
}
