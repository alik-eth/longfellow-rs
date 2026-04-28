//! Zero-knowledge prover for the p7s circuit. Mirrors the structure of
//! `mdoc_zk::prover::MdocZkProver`: loads pre-compiled circuit bytes
//! and stands up Ligero provers over them; the concrete `prove(...)`
//! invocation lives in #95 once the v12 public-input wire layout is
//! ported.
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
    Codec,
    circuit::Circuit,
    fields::{field2_128::Field2_128, fieldp256::FieldP256},
    io::Cursor,
    ligero::{LigeroParameters, prover::LigeroProver},
};
use anyhow::{Context, anyhow};

/// Zero-knowledge prover for the p7s circuit.
///
/// Holds the two decoded circuits + their associated Ligero provers.
/// The actual `prove` entry point — which would parse the witness blob
/// via `parse_witness_blob`, fill circuit-side public/private inputs,
/// and drive Sumcheck + Ligero — lands in Task #95 once the v12
/// public-input wire-layout is ported.
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
    /// Ligero parameters (`num_columns`, `block_size`, etc.) are not
    /// embedded in the circuit binary; the C++ side derives them at
    /// proof-generation time from `(circuit, kRate, kNreq)`. The Rust
    /// consumer takes them as explicit input — Task #74 (fixture port)
    /// will capture the canonical values from the C++ side and plumb
    /// them through, or #95 will port the derivation directly.
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

    /// Number of public inputs the hash circuit expects. Matches the
    /// C++ `c_hash.npub_in` and is what the v12 public-input filler
    /// (Task #95) must produce field-element-by-field-element.
    pub fn hash_circuit_num_public_inputs(&self) -> usize {
        self.hash_circuit.num_public_inputs()
    }

    /// Number of public inputs the signature circuit expects.
    pub fn signature_circuit_num_public_inputs(&self) -> usize {
        self.signature_circuit.num_public_inputs()
    }
}
