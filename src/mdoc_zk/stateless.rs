//! Stateless v12 mdoc verify wrapper — the no_std-clean verifier entry
//! for the SP1 / riscv32 critical path (Task #3 item 5).
//!
//! Mirrors `p7s_zk::stateless::verify_v12`. The high-level
//! `MdocZkVerifier::verify` is gated to `feature = "prover"` because it
//! reconstructs the circuit statements from CBOR (session-transcript
//! hashing, attribute-identifier CBOR encoding). The no_std verifier
//! path cannot do CBOR parsing; instead the host (the SP1 wrapper)
//! pre-extracts the hashed inputs and hands the verifier the two dense
//! public-input field-element arrays directly.
//!
//! Concretely, `verify_v12` takes:
//!   * the decompressed v12 mdoc circuit bytes (`[sig || hash]`, as
//!     emitted by the C++ `generate_circuit` and decoded by
//!     [`crate::mdoc_zk::common_initialization`]);
//!   * the **hash-circuit public-input array** with the MAC region
//!     zeroed (the host builds every other wire: attributes, time, and
//!     — for v12 — the `contract_hash` / `nullifier` / `binding` /
//!     `escrow` / `enroll_commit` / `enroll_nullifier` block);
//!   * the **signature-circuit public-input array** with the MAC region
//!     zeroed (the host builds `implicit_one`, the issuer public key
//!     and `e_session_transcript`);
//!   * the `session_transcript` bytes used to seed the Fiat-Shamir
//!     transcript;
//!   * the serialized `MdocZkProof` bytes.
//!
//! `verify_v12` derives the MAC verifier key share from the post-commit
//! transcript itself, fills the MAC slots in both statements from the
//! proof's `mac_tags`, and then runs the circuit-agnostic Sumcheck +
//! Ligero verification. This is exactly the MAC handling that
//! `MdocZkVerifier::verify` performs after `CircuitStatements::new`; the
//! only thing factored out to the host is the CBOR-bound statement
//! construction.

use crate::{
    ParameterizedCodec,
    fields::{
        CodecFieldElement, FieldElement, field2_128::Field2_128,
        fieldp256::FieldP256,
    },
    io::Cursor,
    mdoc_zk::{
        CircuitVersion, MdocZkProof,
        layout::InputLayout,
        verifier::MdocZkVerifier,
    },
    sumcheck::{SumcheckProtocol, initialize_transcript},
    transcript::{Transcript, TranscriptMode},
};
use alloc::vec::Vec;
use anyhow::{Context, anyhow};

/// Public outputs extracted from a verified v12 mdoc proof.
///
/// The v12 hash circuit exposes the `nullifier`, `binding`, `escrow`,
/// `enroll_commit` and `enroll_nullifier` public-output bit-strings (plus
/// the `contract_hash` input). These are part of the caller-supplied
/// hash statement; `verify_v12` echoes them back so a consumer that
/// trusts the proof can read the issuer-pseudonym / sybil-resistance
/// outputs without re-deriving the bit-string layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdocV12PublicOutputs {
    /// Per-app nullifier — `SHA-256(0x01 || holder_seed || contract_hash || ...)`.
    pub nullifier: [u8; 32],
    /// Holder-binding digest.
    pub binding: [u8; 32],
    /// Identity-escrow digest.
    pub escrow: [u8; 32],
    /// Enrollment commitment — `SHA-256(0x03 || holder_seed)`.
    pub enroll_commit: [u8; 32],
    /// Enrollment nullifier — `SHA-256(0x02 || stable_id || DOMAIN_SEP)`.
    pub enroll_nullifier: [u8; 32],
}

/// Re-pack a 256-wire `Field2_128` v256-hash bit-string back into a
/// 32-byte digest.
///
/// The v12 hash circuit emits each hash output via the C++
/// `push_v256_hash` convention (`vendor/longfellow-zk/lib/circuits/mdoc/
/// mdoc_zk.cc`): wire `j` (0..255) holds bit `j % 8` of byte
/// `(255 - j) / 8` of the digest. This function is the exact inverse.
fn bits_to_bytes(bits: &[Field2_128; 256]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (j, wire) in bits.iter().enumerate() {
        if *wire == Field2_128::ONE {
            let byte_idx = (255 - j) / 8;
            let bit_idx = j % 8;
            out[byte_idx] |= 1 << bit_idx;
        }
    }
    out
}

/// Decode a dense public-input array of `count` field elements from a
/// raw byte blob (each element `FE::num_bytes()` wide, little-endian —
/// the field `Codec` wire format).
fn decode_statement<FE>(blob: &[u8], count: usize) -> Result<Vec<FE>, anyhow::Error>
where
    FE: CodecFieldElement,
{
    let element_bytes = FE::num_bytes();
    let expected = count
        .checked_mul(element_bytes)
        .ok_or_else(|| anyhow!("statement length overflow"))?;
    if blob.len() != expected {
        return Err(anyhow!(
            "statement blob is {} bytes, expected {} ({} elements x {} bytes)",
            blob.len(),
            expected,
            count,
            element_bytes
        ));
    }
    let mut cursor = Cursor::new(blob);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(FE::decode(&mut cursor)?);
    }
    Ok(out)
}

/// Stateless v12 mdoc verify against caller-supplied circuit bytes.
///
/// `circuit_bytes` must be the **decompressed** `[sig || hash]` blob
/// (the host owns zstd). `hash_statement_blob` / `signature_statement_blob`
/// are the dense public-input arrays with the MAC region zeroed,
/// serialized as concatenated little-endian field elements.
///
/// Returns the extracted v12 public outputs on success; an `Err`
/// otherwise. no_std-clean: builds under
/// `--features verifier --no-default-features`.
pub fn verify_v12_with_circuit(
    circuit_bytes: &[u8],
    num_attributes: usize,
    hash_statement_blob: &[u8],
    signature_statement_blob: &[u8],
    session_transcript: &[u8],
    proof_bytes: &[u8],
) -> Result<MdocV12PublicOutputs, anyhow::Error> {
    let verifier = MdocZkVerifier::new(circuit_bytes, CircuitVersion::V12, num_attributes)
        .context("mdoc verify_v12: MdocZkVerifier::new failed")?;

    let layout = InputLayout::new(
        CircuitVersion::V12,
        num_attributes
            .try_into()
            .map_err(|_| anyhow!("unsupported number of attributes"))?,
    )?;

    // Decode the two dense statement arrays.
    let mut hash_statement =
        decode_statement::<Field2_128>(hash_statement_blob, layout.hash_statement_length())
            .context("mdoc verify_v12: decode hash statement")?;
    let mut signature_statement = decode_statement::<FieldP256>(
        signature_statement_blob,
        layout.signature_statement_length(),
    )
    .context("mdoc verify_v12: decode signature statement")?;

    // Parse the proof.
    let context = verifier.proof_context();
    let proof = MdocZkProof::get_decoded_with_param(&context, proof_bytes)
        .context("mdoc verify_v12: could not parse proof")?;

    // Initialize Fiat-Shamir transcript and absorb both commitments —
    // mirrors `MdocZkVerifier::verify`.
    let mut transcript = Transcript::new(session_transcript, TranscriptMode::Normal)?;
    transcript.write_byte_array(proof.hash_commitment.as_bytes())?;
    transcript.write_byte_array(proof.signature_commitment.as_bytes())?;

    // Derive the MAC verifier key share from the post-commit transcript.
    let mac_verifier_key_share = transcript.generate_challenge::<Field2_128>(1)?[0];

    // Fill the MAC region of both statements from the proof's mac_tags
    // and the derived key share, exactly as `CircuitStatements::new`
    // does. The host left these wires zeroed.
    {
        let split = layout.split_hash_statement(&mut hash_statement);
        split.mac_tags.copy_from_slice(&proof.mac_tags);
        *split.mac_verifier_key_share = mac_verifier_key_share;
    }
    {
        let split = layout.split_signature_statement(&mut signature_statement);
        for (tag, wires) in proof
            .mac_tags
            .iter()
            .zip(split.mac_tags.chunks_exact_mut(128))
        {
            for (bit, wire) in tag.iter_bits().zip(wires.iter_mut()) {
                *wire = FieldP256::from_u128(bit as u128);
            }
        }
        for (bit, wire) in mac_verifier_key_share
            .iter_bits()
            .zip(split.mac_verifier_key_share.iter_mut())
        {
            *wire = FieldP256::from_u128(bit as u128);
        }
    }

    // Extract the v12 public outputs from the (now-complete) hash
    // statement before it is consumed by Sumcheck.
    let outputs = {
        let split = layout.split_hash_statement(&mut hash_statement);
        let v12 = split
            .v12_public
            .ok_or_else(|| anyhow!("mdoc verify_v12: hash statement carries no v12 block"))?;
        MdocV12PublicOutputs {
            nullifier: bits_to_bytes(v12.nullifier),
            binding: bits_to_bytes(v12.binding),
            escrow: bits_to_bytes(v12.escrow),
            enroll_commit: bits_to_bytes(v12.enroll_commit),
            enroll_nullifier: bits_to_bytes(v12.enroll_nullifier),
        }
    };

    // Sanity-check the statement lengths against the decoded circuits.
    if hash_statement.len() != verifier.hash_circuit_num_public_inputs() {
        return Err(anyhow!(
            "hash statement length {} != hash circuit npub {}",
            hash_statement.len(),
            verifier.hash_circuit_num_public_inputs()
        ));
    }
    if signature_statement.len() != verifier.signature_circuit_num_public_inputs() {
        return Err(anyhow!(
            "signature statement length {} != signature circuit npub {}",
            signature_statement.len(),
            verifier.signature_circuit_num_public_inputs()
        ));
    }

    // Run Sumcheck + Ligero on the hash circuit.
    initialize_transcript(&mut transcript, verifier.hash_circuit(), &hash_statement)?;
    let hash_linear_constraints = SumcheckProtocol::new(verifier.hash_circuit())
        .linear_constraints(&hash_statement, &mut transcript, &proof.hash_sumcheck_proof)?;
    verifier.hash_ligero_verifier().verify(
        proof.hash_commitment,
        &proof.hash_ligero_proof,
        &mut transcript,
        &hash_linear_constraints,
    )?;

    // Run Sumcheck + Ligero on the signature circuit.
    initialize_transcript(
        &mut transcript,
        verifier.signature_circuit(),
        &signature_statement,
    )?;
    let signature_linear_constraints = SumcheckProtocol::new(verifier.signature_circuit())
        .linear_constraints(
            &signature_statement,
            &mut transcript,
            &proof.signature_sumcheck_proof,
        )?;
    verifier.signature_ligero_verifier().verify(
        proof.signature_commitment,
        &proof.signature_ligero_proof,
        &mut transcript,
        &signature_linear_constraints,
    )?;

    Ok(outputs)
}

/// Stateless v12 mdoc verify against the process-baked v12 circuit
/// fixture ([`crate::circuit_data::MDOC_CIRCUIT_V12_ZST`]).
///
/// Convenience wrapper for `prover`-feature consumers (it owns the zstd
/// decompression). Verifier-only builds receive raw circuit bytes from
/// the host and call [`verify_v12_with_circuit`] directly.
#[cfg(feature = "prover")]
pub fn verify_v12(
    num_attributes: usize,
    hash_statement_blob: &[u8],
    signature_statement_blob: &[u8],
    session_transcript: &[u8],
    proof_bytes: &[u8],
) -> Result<MdocV12PublicOutputs, anyhow::Error> {
    let circuit_bytes = crate::circuit_data::mdoc_circuit_v12_decompressed();
    verify_v12_with_circuit(
        circuit_bytes,
        num_attributes,
        hash_statement_blob,
        signature_statement_blob,
        session_transcript,
        proof_bytes,
    )
}
