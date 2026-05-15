//! Zero-knowledge verifier for the p7s circuit. Verifier-only; works
//! under `--features verifier --no-default-features` (the SP1 critical
//! path). Mirrors the structure of `mdoc_zk::verifier::MdocZkVerifier`.

use crate::{
    Codec, ParameterizedCodec,
    circuit::Circuit,
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    io::Cursor,
    ligero::{LigeroParameters, verifier::LigeroVerifier},
    p7s_zk::{
        layout::{
            BLOB_SCHEMA_VERSION, HASH_PUB_TOTAL, SIG_PUB_TOTAL, build_hash_public_region,
            build_sig_public_region, fill_hash_mac_region, fill_sig_mac_region,
            split_hash_statement, split_sig_statement,
        },
        parser::parse_public_blob,
        proof::{P7sProofContext, P7sZkProof},
        public_inputs::ParsedPublic,
    },
    sumcheck::{SumcheckProtocol, initialize_transcript},
    transcript::{Transcript, TranscriptMode},
};
use alloc::vec::Vec;
use anyhow::{Context, anyhow};

#[cfg(feature = "prover")]
use crate::p7s_zk::prover::{P7sV12PublicOutputs, TRANSCRIPT_SEED};

/// Fiat-Shamir transcript seed (verifier-only feature build mirrors the
/// prover constant; duplicated here so the verifier can be built with
/// `--no-default-features --features verifier`).
#[cfg(not(feature = "prover"))]
const TRANSCRIPT_SEED: &[u8] = b"p7s-7-hash";

/// Verifier-side mirror of the prover's `P7sV12PublicOutputs` struct.
/// Duplicated under verifier-only builds so the verifier can return the
/// extracted public outputs without depending on the prover module.
#[cfg(not(feature = "prover"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P7sV12PublicOutputs {
    pub nullifier: [u8; 32],
    pub enroll_commit: [u8; 32],
    pub enroll_nullifier: [u8; 32],
    pub trust_anchor_index: u32,
}

#[cfg(not(feature = "prover"))]
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

/// Zero-knowledge verifier for the p7s circuit.
pub struct P7sZkVerifier {
    pub(crate) hash_circuit: Circuit<Field2_128>,
    pub(crate) hash_ligero_verifier: LigeroVerifier<Field2_128>,
    pub(crate) signature_circuit: Circuit<FieldP256>,
    pub(crate) signature_ligero_verifier: LigeroVerifier<FieldP256>,
}

impl P7sZkVerifier {
    /// Construct a verifier from the back-to-back-encoded p7s circuit
    /// bytes plus host-supplied Ligero parameters.
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

        let hash_ligero_verifier = LigeroVerifier::new(&hash_circuit, hash_ligero_parameters);
        let signature_ligero_verifier =
            LigeroVerifier::new(&signature_circuit, signature_ligero_parameters);

        Ok(Self {
            hash_circuit,
            hash_ligero_verifier,
            signature_circuit,
            signature_ligero_verifier,
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

    /// Borrowed proof-context view, for codec round-trips on the verifier side.
    pub fn proof_context(&self) -> P7sProofContext<'_> {
        P7sProofContext {
            hash_circuit: &self.hash_circuit,
            signature_circuit: &self.signature_circuit,
            hash_layout: self.hash_ligero_verifier.tableau_layout(),
            signature_layout: self.signature_ligero_verifier.tableau_layout(),
        }
    }

    /// Verify a v12 p7s proof. Returns the extracted public outputs on
    /// success.
    ///
    /// Mirrors C++ `verify(...)` at `p7s_zk.cc:2730-...`. The canonical
    /// sequence is:
    ///   1. Parse public blob.
    ///   2. Strip the schema-version u32 prefix; decode the proof bytes.
    ///   3. Initialize Fiat-Shamir transcript with `TRANSCRIPT_SEED`.
    ///   4. Receive both commitments to mirror the prover's FS interleave.
    ///   5. Sample `av` from the post-commit transcript.
    ///   6. Build public-input dense arrays for both circuits;
    ///      overwrite MAC region with the proof's `mac_values` + sampled `av`.
    ///   7. Run Sumcheck + Ligero verify on the hash circuit.
    ///   8. Run Sumcheck + Ligero verify on the sig circuit.
    ///   9. Return extracted public outputs.
    pub fn verify(
        &self,
        public_blob: &[u8],
        proof_bytes: &[u8],
    ) -> Result<P7sV12PublicOutputs, anyhow::Error> {
        // 1. Parse public blob.
        let pub_ = parse_public_blob(public_blob).context("parse public blob")?;

        // 2. Strip schema-version u32 LE prefix; decode proof.
        if proof_bytes.len() < 4 {
            return Err(anyhow!("proof bytes too short for schema version"));
        }
        let mut sv_bytes = [0u8; 4];
        sv_bytes.copy_from_slice(&proof_bytes[..4]);
        let schema = u32::from_le_bytes(sv_bytes);
        if schema != BLOB_SCHEMA_VERSION {
            return Err(anyhow!(
                "proof schema mismatch: got {} expected {}",
                schema,
                BLOB_SCHEMA_VERSION
            ));
        }
        let context = self.proof_context();
        let mut cursor = Cursor::new(&proof_bytes[4..]);
        let proof = P7sZkProof::decode_with_param(&context, &mut cursor)
            .context("decode p7s proof")?;
        if cursor.position() as usize != proof_bytes.len() - 4 {
            return Err(anyhow!("trailing bytes after proof decode"));
        }

        // 3. Initialize Fiat-Shamir transcript.
        let mut transcript = Transcript::new(TRANSCRIPT_SEED, TranscriptMode::Normal)?;

        // 4. Receive both commitments.
        transcript.write_byte_array(proof.hash_commitment.as_bytes())?;
        transcript.write_byte_array(proof.signature_commitment.as_bytes())?;

        // 5. Sample av from post-commit transcript.
        let av_arr = transcript.generate_challenge(1)?;
        let av = av_arr[0];

        // 6. Build public-input dense arrays + overwrite MAC region.
        let mut pub_hash = build_hash_public_region(&pub_);
        let mut pub_sig = build_sig_public_region(&pub_);
        {
            let mut hv = split_hash_statement(&mut pub_hash);
            fill_hash_mac_region(&mut hv, &proof.mac_values, &av);
        }
        {
            let mut sv = split_sig_statement(&mut pub_sig);
            fill_sig_mac_region(&mut sv, &proof.mac_values, &av);
        }
        debug_assert_eq!(pub_hash.len(), HASH_PUB_TOTAL);
        debug_assert_eq!(pub_sig.len(), SIG_PUB_TOTAL);

        if pub_hash.len() != self.hash_circuit.num_public_inputs() {
            return Err(anyhow!(
                "hash public input length {} != hash_circuit.num_public_inputs() {}",
                pub_hash.len(),
                self.hash_circuit.num_public_inputs()
            ));
        }
        if pub_sig.len() != self.signature_circuit.num_public_inputs() {
            return Err(anyhow!(
                "sig public input length {} != signature_circuit.num_public_inputs() {}",
                pub_sig.len(),
                self.signature_circuit.num_public_inputs()
            ));
        }

        // 7. Sumcheck + Ligero verify on hash circuit.
        initialize_transcript(&mut transcript, &self.hash_circuit, &pub_hash)?;
        let hash_lc = SumcheckProtocol::new(&self.hash_circuit).linear_constraints(
            &pub_hash,
            &mut transcript,
            &proof.hash_sumcheck_proof,
        )?;
        self.hash_ligero_verifier.verify(
            proof.hash_commitment,
            &proof.hash_ligero_proof,
            &mut transcript,
            &hash_lc,
        )?;

        // 8. Sumcheck + Ligero verify on sig circuit.
        initialize_transcript(&mut transcript, &self.signature_circuit, &pub_sig)?;
        let sig_lc = SumcheckProtocol::new(&self.signature_circuit).linear_constraints(
            &pub_sig,
            &mut transcript,
            &proof.signature_sumcheck_proof,
        )?;
        self.signature_ligero_verifier.verify(
            proof.signature_commitment,
            &proof.signature_ligero_proof,
            &mut transcript,
            &sig_lc,
        )?;

        // 9. Extract public outputs.
        Ok(P7sV12PublicOutputs::from(&pub_))
    }
}

/// Stateless verifier-only v12 p7s verify against caller-supplied
/// circuit bytes.
///
/// no_std-clean mirror of [`crate::mdoc_zk::stateless::verify_v12_with_circuit`].
/// Unlike [`crate::p7s_zk::stateless::verify_v12`] (which is `prover`-gated
/// because it owns the zstd decompression of the baked circuit fixture),
/// this entry point takes the **already-decompressed** `[hash || sig]`
/// circuit blob and is therefore the SP1 / riscv32 guest entry point.
///
/// `circuit_bytes` is the decompressed back-to-back-encoded p7s v12
/// circuit blob; `public_blob` is the parsed-public input blob; `proof`
/// is the serialized p7s proof (4-byte schema prefix + body).
///
/// Builds under `--features verifier --no-default-features`.
pub fn verify_v12_with_circuit(
    circuit_bytes: &[u8],
    public_blob: &[u8],
    proof: &[u8],
) -> Result<P7sV12PublicOutputs, anyhow::Error> {
    use crate::p7s_zk::params::{P7S_NREQ, P7S_RATE_INV, default_ligero_params_for_circuit};
    use crate::fields::CodecFieldElement;

    // Decode the back-to-back circuits to derive the default Ligero
    // parameters (mirrors `p7s_zk::stateless::derive_default_params`).
    let mut cursor = Cursor::new(circuit_bytes);
    let hash_circuit = Circuit::<Field2_128>::decode(&mut cursor)
        .context("p7s verify_v12_with_circuit: hash circuit decode")?;
    let sig_circuit = Circuit::<FieldP256>::decode(&mut cursor)
        .context("p7s verify_v12_with_circuit: sig circuit decode")?;
    if cursor.position() as usize != circuit_bytes.len() {
        return Err(anyhow!(
            "p7s verify_v12_with_circuit: trailing bytes after both circuits decode"
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

    let verifier = P7sZkVerifier::new(circuit_bytes, hash_params, sig_params)
        .context("p7s verify_v12_with_circuit: P7sZkVerifier::new failed")?;
    verifier.verify(public_blob, proof)
}

/// Suppress unused-warning when verifier-only build path doesn't reach the
/// `Vec` import via this module.
#[allow(dead_code)]
fn _vec_keep_alive(_v: Vec<u8>) {}

/// Module-level shim so the symbol `ParsedPublic` is treated as referenced
/// across cfg paths (verifier-only build).
#[allow(dead_code)]
fn _parsed_public_referenced(_p: &ParsedPublic) {}
