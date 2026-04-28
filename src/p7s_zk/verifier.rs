//! Zero-knowledge verifier for the p7s circuit. Verifier-only; works
//! under `--features verifier --no-default-features` (the SP1 critical
//! path). Mirrors the structure of `mdoc_zk::verifier::MdocZkVerifier`.
//!
//! The high-level `verify(public_blob, proof)` entry — which would
//! parse the public blob, decode the proof, fill circuit-side public
//! inputs, and run Sumcheck + Ligero verification — lands in Task #95.
//! The constructor here just stands up the Ligero verifiers from the
//! pre-compiled circuit bytes.

use crate::{
    Codec,
    circuit::Circuit,
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    io::Cursor,
    ligero::{LigeroParameters, verifier::LigeroVerifier},
};
use anyhow::{Context, anyhow};

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
    ///
    /// See `P7sZkProver::new` for why the parameters are passed in
    /// rather than derived; the same constraint applies on the verifier
    /// side.
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
}
