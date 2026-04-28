//! Zero-knowledge prover for the p7s circuit. Mirrors the structure of
//! `mdoc_zk::prover::MdocZkProver`: loads pre-compiled circuit bytes
//! and stands up Ligero provers over them; `prove(...)` drives the full
//! Sumcheck + Ligero protocol over the v12 witness/public blob pair.
//!
//! The pre-compiled p7s circuit binary (produced by the C++ side's
//! `circuits/p7s/circuit_maker.cc`) packs two circuits back-to-back:
//!   * hash circuit over GF(2^128) (builds invariants 9, 4, 5, 6, 10,
//!     2b, 2c, 7, 12, 13, 14, MAC plumbing for `e` and `e2`).
//!   * signature circuit over Fp256Base (builds invariants 1 + 2a
//!     ECDSA verifications, MAC plumbing).
//! `Circuit::decode` reads them sequentially; the same convention as
//! `mdoc_zk::common_initialization`.

use crate::{
    Codec, ParameterizedCodec,
    circuit::Circuit,
    fields::{CodecFieldElement, FieldElement, field2_128::Field2_128, fieldp256::FieldP256},
    io::Cursor,
    ligero::{LigeroParameters, prover::LigeroProver},
    p7s_zk::{
        ecdsa_witness::compute_ecdsa_witness_wires,
        layout::{
            BLOB_SCHEMA_VERSION, HASH_PUB_TOTAL, SIG_PUB_TOTAL, SPKI_PREFIX_LEN,
            build_hash_public_region, build_sig_public_region, fill_hash_mac_region,
            fill_sig_mac_region, split_hash_statement, split_sig_statement,
        },
        mac::{
            FIELD2_128_BYTES, TOTAL_MAC_VALUES, compute_all_macs, field_to_le_bytes, sample_ap,
        },
        parser::{parse_public_blob, parse_witness_blob},
        proof::{P7sProofContext, P7sZkProof},
        public_inputs::ParsedPublic,
        trust_anchors::trust_anchor_pk,
        witness::ParsedWitness,
        witness_fill::{
            HashSideShaWitnesses, SPKI_XY_LEN, append_hash_private_region,
            append_sig_private_region,
        },
    },
    sumcheck::{ProverResult, SumcheckProtocol, initialize_transcript},
    transcript::{Transcript, TranscriptMode},
    witness::Witness,
};
use alloc::vec::Vec;
use anyhow::{Context, anyhow};
use rand::RngCore;

/// Fiat-Shamir transcript seed for the dual-circuit p7s prover/verifier.
///
/// Mirrors C++ `kHashTranscriptSeed = "p7s-7-hash"` — 10 ASCII bytes.
pub(crate) const TRANSCRIPT_SEED: &[u8] = b"p7s-7-hash";

/// Zero-knowledge prover for the p7s circuit.
pub struct P7sZkProver {
    pub(crate) hash_circuit: Circuit<Field2_128>,
    pub(crate) hash_ligero_prover: LigeroProver<Field2_128>,
    pub(crate) signature_circuit: Circuit<FieldP256>,
    pub(crate) signature_ligero_prover: LigeroProver<FieldP256>,
}

impl P7sZkProver {
    /// Construct a prover from the back-to-back-encoded p7s circuit
    /// bytes plus host-supplied Ligero parameters for each circuit.
    ///
    /// # Errors
    /// Returns an error if either circuit fails to decode, or if the
    /// circuit byte buffer has trailing data after both circuits parse.
    pub fn new(
        circuit_bytes: &[u8],
        hash_ligero_parameters: LigeroParameters,
        signature_ligero_parameters: LigeroParameters,
    ) -> Result<Self, anyhow::Error> {
        let mut cursor = Cursor::new(circuit_bytes);
        let hash_circuit = Circuit::<Field2_128>::decode(&mut cursor)
            .context("p7s: failed to decode hash circuit")?;
        let signature_circuit = Circuit::<FieldP256>::decode(&mut cursor)
            .context("p7s: failed to decode signature circuit")?;
        if cursor.position() as usize != circuit_bytes.len() {
            return Err(anyhow!(
                "p7s: extra data left over after decoding both circuits"
            ));
        }

        let hash_ligero_prover = LigeroProver::new(&hash_circuit, hash_ligero_parameters);
        let signature_ligero_prover =
            LigeroProver::new(&signature_circuit, signature_ligero_parameters);

        Ok(Self {
            hash_circuit,
            hash_ligero_prover,
            signature_circuit,
            signature_ligero_prover,
        })
    }

    /// Number of public inputs the hash circuit expects.
    pub fn hash_circuit_num_public_inputs(&self) -> usize {
        self.hash_circuit.num_public_inputs()
    }

    /// Number of public inputs the signature circuit expects.
    pub fn signature_circuit_num_public_inputs(&self) -> usize {
        self.signature_circuit.num_public_inputs()
    }

    /// Generate a v12 p7s proof from a parsed witness/public blob pair.
    ///
    /// Returns the serialized proof bytes (schema-version-prefixed,
    /// self-delimiting binary — see `proof.rs`).
    ///
    /// Mirrors the C++ `prove(...)` orchestration at
    /// `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:2440-2725`. The
    /// canonical sequence is:
    ///   1. Parse + sanity-check witness/public blobs.
    ///   2. Sample 8 prover-share `ap` halves (`Field2_128`).
    ///   3. Build hash-side dense vector with MAC region zero-placeholders.
    ///   4. Build sig-side dense vector with MAC region zero-placeholders.
    ///   5. Initialize Fiat-Shamir transcript with `TRANSCRIPT_SEED`.
    ///   6. Commit both circuits BEFORE sampling `av`.
    ///   7. Sample `av` from the post-commit transcript.
    ///   8. Compute the 8 MAC values from `(av, ap, e/e2/spki_x/spki_y)`.
    ///   9. Overwrite MAC regions in both dense arrays.
    ///   10. Evaluate both circuits to extended witnesses.
    ///   11. Run Sumcheck + Ligero on the hash circuit.
    ///   12. Run Sumcheck + Ligero on the sig circuit.
    ///   13. Serialize the proof.
    pub fn prove(
        &self,
        witness_blob: &[u8],
        public_blob: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        // 1. Parse blobs.
        let wit = parse_witness_blob(witness_blob).context("parse witness blob")?;
        let pub_ = parse_public_blob(public_blob).context("parse public blob")?;
        if wit.trust_anchor_index != pub_.trust_anchor_index {
            return Err(anyhow!(
                "trust_anchor_index mismatch: witness={} public={}",
                wit.trust_anchor_index,
                pub_.trust_anchor_index
            ));
        }

        // Sanity-check decoded circuit shape.
        if self.hash_circuit.num_public_inputs() != HASH_PUB_TOTAL {
            return Err(anyhow!(
                "hash circuit num_public_inputs={} expected {}",
                self.hash_circuit.num_public_inputs(),
                HASH_PUB_TOTAL
            ));
        }
        if self.signature_circuit.num_public_inputs() != SIG_PUB_TOTAL {
            return Err(anyhow!(
                "signature circuit num_public_inputs={} expected {}",
                self.signature_circuit.num_public_inputs(),
                SIG_PUB_TOTAL
            ));
        }

        // 2. Sample 8 prover-share ap halves.
        let ap_vec = sample_ap(TOTAL_MAC_VALUES);
        let ap: [Field2_128; TOTAL_MAC_VALUES] = ap_vec
            .try_into()
            .map_err(|_| anyhow!("sample_ap returned wrong length"))?;

        // 3-4. Build hash + sig dense arrays (public region only; MAC region
        //      placeholder-zero, will be overwritten after commit).
        let mut w_hash = build_hash_public_region(&pub_);
        let mut w_sig = build_sig_public_region(&pub_);

        // Append hash-side private region — also returns the cert SHA + e/e2
        // digests we'll re-use on the sig side.
        let HashSideShaWitnesses {
            cert_sw: _cert_sw,
            e_digest_be,
            e2_digest_be,
        } = append_hash_private_region(&mut w_hash, &wit, &pub_, &ap);

        // Sanity: hash circuit total wire count.
        if w_hash.len() != self.hash_circuit.num_inputs() {
            return Err(anyhow!(
                "hash dense vector length {} != hash_circuit.num_inputs() {}",
                w_hash.len(),
                self.hash_circuit.num_inputs()
            ));
        }

        // Extract holder pk X/Y from cert_tbs SPKI window. C++:
        // `kSpkiXAbs = wit.cert_tbs_spki_offset + kSpkiPrefixLen + 1`
        // (`p7s_zk.cc:2402-2412`). The +1 skips the SEC1 0x04 uncompressed tag.
        let spki_x_abs = (wit.cert_tbs_spki_offset as usize)
            .checked_add(SPKI_PREFIX_LEN)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| anyhow!("SPKI X offset overflow"))?;
        let spki_y_abs = spki_x_abs
            .checked_add(SPKI_XY_LEN)
            .ok_or_else(|| anyhow!("SPKI Y offset overflow"))?;
        if spki_y_abs + SPKI_XY_LEN > wit.cert_tbs.len() {
            return Err(anyhow!("SPKI window past cert_tbs end"));
        }
        let mut spki_x_be = [0u8; SPKI_XY_LEN];
        let mut spki_y_be = [0u8; SPKI_XY_LEN];
        spki_x_be.copy_from_slice(&wit.cert_tbs[spki_x_abs..spki_x_abs + SPKI_XY_LEN]);
        spki_y_be.copy_from_slice(&wit.cert_tbs[spki_y_abs..spki_y_abs + SPKI_XY_LEN]);

        // Compute ECDSA witness wires for the cert sig (root pubkey from
        // trust-anchor table) and the content sig (holder pubkey from SPKI).
        let (root_pk_x, root_pk_y) = trust_anchor_pk(wit.trust_anchor_index)
            .ok_or_else(|| anyhow!("trust anchor index out of range"))?;
        let cert_ecdsa_wires = compute_ecdsa_witness_wires(
            root_pk_x,
            root_pk_y,
            &e_digest_be,
            &wit.cert_sig_r,
            &wit.cert_sig_s,
        )
        .context("cert ECDSA witness")?;

        let holder_pk_x_field = field_p256_from_be_bytes(&spki_x_be)
            .ok_or_else(|| anyhow!("holder pk X parse failed"))?;
        let holder_pk_y_field = field_p256_from_be_bytes(&spki_y_be)
            .ok_or_else(|| anyhow!("holder pk Y parse failed"))?;
        let content_ecdsa_wires = compute_ecdsa_witness_wires(
            holder_pk_x_field,
            holder_pk_y_field,
            &e2_digest_be,
            &wit.content_sig_r,
            &wit.content_sig_s,
        )
        .context("content ECDSA witness")?;

        // Append sig-side private region.
        append_sig_private_region(
            &mut w_sig,
            &spki_x_be,
            &spki_y_be,
            &e_digest_be,
            &e2_digest_be,
            &spki_x_be,
            &spki_y_be,
            &ap,
            &cert_ecdsa_wires,
            &content_ecdsa_wires,
        );

        // Sanity: sig circuit total wire count.
        if w_sig.len() != self.signature_circuit.num_inputs() {
            return Err(anyhow!(
                "sig dense vector length {} != signature_circuit.num_inputs() {}",
                w_sig.len(),
                self.signature_circuit.num_inputs()
            ));
        }

        // 5. Initialize Fiat-Shamir transcript.
        let mut transcript = Transcript::new(TRANSCRIPT_SEED, TranscriptMode::Normal)?;

        // Build Ligero witnesses with one-time pads.
        let mut rng = rand::rng();
        let mut buffer_h = alloc::vec![0u8; Field2_128::num_bytes()];
        let hash_witness = Witness::fill_witness(
            self.hash_ligero_prover.witness_layout().clone(),
            &w_hash[self.hash_circuit.num_public_inputs()..],
            || Field2_128::sample_from_source(&mut buffer_h, |bytes| rng.fill_bytes(bytes)),
        );
        let mut buffer_s = alloc::vec![0u8; FieldP256::num_bytes()];
        let signature_witness = Witness::fill_witness(
            self.signature_ligero_prover.witness_layout().clone(),
            &w_sig[self.signature_circuit.num_public_inputs()..],
            || FieldP256::sample_from_source(&mut buffer_s, |bytes| rng.fill_bytes(bytes)),
        );

        // 6. Commit BOTH circuits before sampling av.
        let hash_commitment_state = self.hash_ligero_prover.commit(&hash_witness)?;
        transcript.write_byte_array(hash_commitment_state.commitment().as_bytes())?;
        let signature_commitment_state =
            self.signature_ligero_prover.commit(&signature_witness)?;
        transcript.write_byte_array(signature_commitment_state.commitment().as_bytes())?;

        // 7. Sample av from post-commit transcript.
        let av_arr = transcript.generate_challenge(1)?;
        let av = av_arr[0];

        // 8. Compute MACs over the 4 LE-byte messages (e, e2, spki_x, spki_y).
        let e_le = reverse_to_le(&e_digest_be);
        let e2_le = reverse_to_le(&e2_digest_be);
        let spki_x_le = reverse_to_le(&spki_x_be);
        let spki_y_le = reverse_to_le(&spki_y_be);
        let macs = compute_all_macs(&av, &ap, &e_le, &e2_le, &spki_x_le, &spki_y_le);

        // 9. Overwrite MAC region in BOTH dense arrays.
        {
            let mut hash_view = split_hash_statement(&mut w_hash[..HASH_PUB_TOTAL]);
            fill_hash_mac_region(&mut hash_view, &macs, &av);
        }
        {
            let mut sig_view = split_sig_statement(&mut w_sig[..SIG_PUB_TOTAL]);
            fill_sig_mac_region(&mut sig_view, &macs, &av);
        }

        // 10. Evaluate both circuits.
        let hash_evaluation = self.hash_circuit.evaluate(&w_hash)?;
        let signature_evaluation = self.signature_circuit.evaluate(&w_sig)?;

        // 11. Sumcheck + Ligero on hash circuit.
        initialize_transcript(
            &mut transcript,
            &self.hash_circuit,
            hash_evaluation.public_inputs(self.hash_circuit.num_public_inputs()),
        )?;
        let ProverResult {
            proof: hash_sumcheck_proof,
            linear_constraints: hash_lc,
        } = SumcheckProtocol::new(&self.hash_circuit).prove(
            &hash_evaluation,
            &mut transcript,
            &hash_witness,
        )?;
        let hash_ligero_proof =
            self.hash_ligero_prover
                .prove(&mut transcript, &hash_commitment_state, &hash_lc)?;

        // 12. Sumcheck + Ligero on sig circuit.
        initialize_transcript(
            &mut transcript,
            &self.signature_circuit,
            signature_evaluation.public_inputs(self.signature_circuit.num_public_inputs()),
        )?;
        let ProverResult {
            proof: signature_sumcheck_proof,
            linear_constraints: signature_lc,
        } = SumcheckProtocol::new(&self.signature_circuit).prove(
            &signature_evaluation,
            &mut transcript,
            &signature_witness,
        )?;
        let signature_ligero_proof = self.signature_ligero_prover.prove(
            &mut transcript,
            &signature_commitment_state,
            &signature_lc,
        )?;

        // 13. Serialize: schema_version u32 (LE) || P7sZkProof.
        let proof = P7sZkProof {
            mac_values: macs,
            hash_commitment: *hash_commitment_state.commitment(),
            hash_sumcheck_proof,
            hash_ligero_proof,
            signature_commitment: *signature_commitment_state.commitment(),
            signature_sumcheck_proof,
            signature_ligero_proof,
        };
        let context = P7sProofContext {
            hash_circuit: &self.hash_circuit,
            signature_circuit: &self.signature_circuit,
            hash_layout: hash_commitment_state.tableau().layout(),
            signature_layout: signature_commitment_state.tableau().layout(),
        };
        let mut out = Vec::with_capacity(1 << 19);
        out.extend_from_slice(&BLOB_SCHEMA_VERSION.to_le_bytes());
        proof.encode_with_param(&context, &mut out)?;
        Ok(out)
    }

}

/// Decode a 32-byte BE buffer to a `FieldP256` element.
fn field_p256_from_be_bytes(be: &[u8; 32]) -> Option<FieldP256> {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    FieldP256::try_from(&le).ok()
}

/// Reverse a 32-byte BE buffer into a 32-byte LE buffer.
fn reverse_to_le(be: &[u8; 32]) -> [u8; 32] {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be[31 - i];
    }
    le
}

/// Outputs extracted from a verified p7s proof. Mirrors the public outputs
/// the C++ `p7s_zk.cc:verify` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P7sV12PublicOutputs {
    /// Per-app nullifier (32 bytes BE).
    pub nullifier: [u8; 32],
    /// Enroll commit (32 bytes BE).
    pub enroll_commit: [u8; 32],
    /// Enroll nullifier (32 bytes BE).
    pub enroll_nullifier: [u8; 32],
    /// Index into the trust-anchor table (`< TRUST_ANCHOR_COUNT`).
    pub trust_anchor_index: u32,
}

impl From<&ParsedPublic> for P7sV12PublicOutputs {
    fn from(p: &ParsedPublic) -> Self {
        Self {
            nullifier: p.nullifier,
            enroll_commit: p.enroll_commit,
            enroll_nullifier: p.enroll_nullifier,
            trust_anchor_index: p.trust_anchor_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p7s_zk::layout::HASH_MAC_INPUT_WIRES;

    #[test]
    fn transcript_seed_is_p7s_7_hash() {
        assert_eq!(TRANSCRIPT_SEED, b"p7s-7-hash");
        assert_eq!(TRANSCRIPT_SEED.len(), 10);
    }

    #[test]
    fn reverse_to_le_swaps_endianness() {
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = i as u8;
        }
        let le = reverse_to_le(&be);
        for i in 0..32 {
            assert_eq!(le[i], (31 - i) as u8);
        }
    }

    #[test]
    fn hash_mac_region_size_matches_constant() {
        assert_eq!(HASH_MAC_INPUT_WIRES, TOTAL_MAC_VALUES + 1);
    }

    /// Ensures we don't break the field2_128 byte size assumption when
    /// constructing the Ligero witness one-time pad buffers.
    #[test]
    fn field2_128_byte_count_matches_mac_byte_count() {
        assert_eq!(<Field2_128 as CodecFieldElement>::num_bytes(), FIELD2_128_BYTES);
    }

    /// `field_to_le_bytes` is referenced for proof-side serialization; the
    /// alias check ensures the import we kept is wired through to the mac
    /// module (regression guard for unused-import drift).
    #[test]
    fn field_to_le_bytes_is_reachable() {
        let bytes = field_to_le_bytes(&Field2_128::ZERO);
        assert_eq!(bytes, [0u8; FIELD2_128_BYTES]);
    }
}
