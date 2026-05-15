use crate::mdoc_zk::{CircuitVersion, prover::MdocZkProver};
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

/// Initialize the prover by loading a decompressed circuit file.
///
/// @param {Uint8Array} circuit - The decompressed circuit file.
/// @param {CircuitVersion} circuit_version - The version of the mdoc_zk circuit interface.
/// @param {number} num_attributes - The number of attributes to be disclosed in the presentation.
/// @returns {MdocZkProver}
#[wasm_bindgen(skip_jsdoc)]
pub fn initialize_prover(
    circuit: &[u8],
    circuit_version: CircuitVersion,
    num_attributes: usize,
) -> Result<MdocZkProver, MdocZkError> {
    MdocZkProver::new(circuit, circuit_version, num_attributes).map_err(convert_error)
}

/// Create a proof for a credential presentation.
///
/// @param {MdocZkProver} prover - The prover returned from `initialize()`.
/// @param {Uint8Array} device_response - The mdoc's DeviceResponse, as CBOR data.
/// @param {string} namespace -  The namespace of the claims.
/// @param {string[]} requested_claims - The identifiers of the claims to be disclosed.
/// @param {Uint8Array} session_transcript - The `SessionTranscript`, as CBOR data.
/// @param {string} time - The current time. This must be in RFC 3339 format, in UTC, with no time zone offset.
/// @returns {Uint8Array} The serialized proof.
#[wasm_bindgen(skip_jsdoc)]
// We have to use `Box<[String]>` because wasm-bindgen does not support `&[String]` arguments.
#[allow(clippy::boxed_local)]
pub fn prove(
    prover: &MdocZkProver,
    device_response: &[u8],
    namespace: &str,
    requested_claims: Box<[String]>,
    session_transcript: &[u8],
    time: &str,
) -> Result<Vec<u8>, MdocZkError> {
    let requested_claims = requested_claims
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    prover
        .prove(
            device_response,
            namespace,
            &requested_claims,
            session_transcript,
            time,
        )
        .map_err(convert_error)
}

#[wasm_bindgen(module = "/js/error.js")]
extern "C" {
    pub type MdocZkError;

    #[wasm_bindgen(constructor)]
    fn new(message: String) -> MdocZkError;
}

fn convert_error(error: anyhow::Error) -> MdocZkError {
    let message = format!("{error:#}");
    MdocZkError::new(message)
}

/// Run one full p7s v12 prove over the embedded TestAnchorA fixture.
///
/// Returns the serialized proof bytes. Browser measurement harness: the
/// circuit is embedded in the wasm module; only the small witness/public
/// fixtures need bundling here.
#[wasm_bindgen]
pub fn p7s_prove_v12_fixture() -> Result<Vec<u8>, JsError> {
    const WITNESS: &[u8] =
        include_bytes!("../tests/fixtures/p7s/blobs/testanchor_a_v12_witness.bin");
    const PUBLIC: &[u8] =
        include_bytes!("../tests/fixtures/p7s/blobs/testanchor_a_v12_public.bin");
    crate::p7s_zk::prove_v12(WITNESS, PUBLIC).map_err(|e| JsError::new(&format!("{e:#}")))
}

/// Current wasm linear-memory size in bytes. wasm memory only ever grows,
/// so reading this immediately after a prove yields that run's peak.
#[wasm_bindgen]
pub fn wasm_memory_bytes() -> f64 {
    (core::arch::wasm32::memory_size(0) as u64 * 65536) as f64
}
