//! `default_ligero_params` — port of the C++ production optimizer at
//! `vendor/longfellow-zk/lib/circuits/mdoc/circuit_maker.cc:64`'s
//! `optimize` function. Iterates candidate `block_enc ∈ [100, 2^17]`
//! over every integer (not just powers of two) and picks the value
//! minimizing serialized proof size for a given (circuit, rate, nreq).
//! Mirrors `LigeroParam::layout()`'s formulas
//! (`vendor/longfellow-zk/lib/ligero/ligero_param.h:185`).
//!
//! Use cases:
//!   * #95: high-level `P7sZkProver::prove` / `P7sZkVerifier::verify`
//!     can derive Ligero parameters from the loaded p7s circuit
//!     directly, eliminating the per-(version, num_attrs) hardcoded
//!     table that ISRG's mdoc port relies on.
//!   * Future predicate-extension circuits: same — no new hardcoded
//!     entries needed.
//!
//! # Tied-proof-size selection
//!
//! Multiple `block_enc` candidates can produce the same minimum proof
//! size. The C++ optimizer (`<` comparison on `min_proof_size`) keeps
//! the FIRST candidate it sees with the minimum, which for its
//! lowest-to-highest iteration is the smallest tied `block_enc`. This
//! Rust port matches that behavior exactly.
//!
//! Caveat: ISRG's `mdoc_zk::{signature,hash}_ligero_parameters`
//! hardcodes `block_enc` values that do NOT match this optimizer for
//! mdoc V6/V7 — they appear to have been chosen at production time by
//! something other than pure proof-size minimization (likely manual
//! power-of-two preference among tied candidates; verified by hand
//! that V6 num_attrs=1 hash circuit's e=4096 and e=3947 both produce
//! 110720 bytes). For p7s usage where the goal is consistent
//! Rust-prover ↔ Rust-verifier agreement, any optimizer-picked value
//! works. Cross-language Rust↔C++ proof-bytes parity (#75/#76) needs
//! C++-exact values; that's #98's territory.
//!
//! # No subfield-bit packing optimism
//!
//! The C++ proof-size estimator counts `req` bytes "optimistically"
//! assuming all elements fit in the field's subfield (`Field::kSubFieldBytes`).
//! For GF(2^128) the subfield is GF(2^16) (2 bytes); for FieldP256 the
//! subfield is itself (32 bytes). This Rust port mirrors that posture
//! exactly, parameterized by `field_subfield_bytes`.

use crate::{
    fields::CodecFieldElement,
    circuit::Circuit,
    ligero::LigeroParameters,
    witness::WitnessLayout,
};

/// p7s-side rate constant. Matches `kRate` in
/// `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:408`.
pub const P7S_RATE_INV: usize = 4;

/// p7s-side nreq constant. Matches `kNreq` in
/// `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc:409`.
pub const P7S_NREQ: usize = 189;

/// Mirror of `vendor/longfellow-zk/lib/merkle/merkle_tree.h:64`'s
/// `merkle_tree_len(n)` — Merkle proof length for `n` leaves.
fn merkle_commitment_len(block_ext: usize) -> usize {
    if block_ext == 0 {
        return 1;
    }
    let mut r: usize = 1;
    let mut pos: usize = block_ext - 1;
    pos = pos.saturating_add(block_ext);
    while pos > 1 {
        r += 1;
        pos >>= 1;
    }
    r
}

/// Layout output: the parameters we'd commit to (matching
/// `LigeroParameters`) plus the proof-size estimate the optimizer
/// minimizes over.
struct LayoutResult {
    nreq: usize,
    witnesses_per_row: usize,
    quadratic_constraints_per_row: usize,
    block_size: usize,
    num_columns: usize,
    proof_size: u64,
}

/// Run a single iteration of `LigeroParam::layout` for a candidate
/// `block_enc`. Returns `None` if the candidate fails any of the
/// validity gates (mirrors C++ `return SIZE_MAX`).
#[allow(clippy::too_many_arguments)]
fn ligero_layout(
    nw: usize,
    nq: usize,
    rate_inv: usize,
    nreq: usize,
    field_bytes: u64,
    field_subfield_bytes: u64,
    digest_bytes: u64,
    nonce_bytes: u64,
    block_enc: usize,
) -> Option<LayoutResult> {
    // Ligero subfield-fit gate: block_enc must fit in the subfield's bit
    // count. We're lenient here — `field_subfield_bytes <= 4` would
    // require block_enc < 2^32 which already passes in our usable range
    // (block_enc < 2^28 from max_lg_size). Encode as `(1 << bits) >
    // block_enc`.
    let max_lg_size: u32 = 28;
    let max_size: usize = 1usize << max_lg_size;
    let subfield_bits = (field_subfield_bytes as u32) * 8;
    if subfield_bits <= max_lg_size {
        if (block_enc as u64) >= (1u64 << subfield_bits) {
            return None;
        }
    }
    if block_enc > max_size || rate_inv > max_size || (block_enc + 1) < (2 + rate_inv) {
        return None;
    }
    let block = (block_enc + 1) / (2 + rate_inv);
    let r = nreq;
    if block < r {
        return None;
    }
    let w = block - r;
    if w < r {
        return None;
    }
    let dblock = 2 * block - 1;
    if block_enc < dblock {
        return None;
    }
    let block_ext = block_enc - dblock;

    let nwrow = nw.div_ceil(w);
    let nqtriples = nq.div_ceil(w);
    let nwqrow = nwrow + 3 * nqtriples;
    let nrow = nwqrow + 3; // three blinding rows.
    if nrow >= max_size / block_enc {
        return None;
    }

    let mc_pathlen = merkle_commitment_len(block_ext);

    // proof size estimate, in u64 to avoid overflow.
    let mut sz: u64 = 0;
    sz += digest_bytes; // commitment
    // merkle openings (approximated)
    sz += (mc_pathlen as u64) / 2 * (nreq as u64) * digest_bytes;
    // y_ldt
    sz += (block as u64) * field_bytes;
    // y_dot
    sz += (dblock as u64) * field_bytes;
    // y_quad: dblock minus w (the middle w elements are zero and not
    // serialized).
    sz += ((dblock - w) as u64) * field_bytes;
    // nonces
    sz += (nreq as u64) * nonce_bytes;
    // req — assume all elements are in the subfield
    sz += (nrow as u64) * (nreq as u64) * field_subfield_bytes;

    Some(LayoutResult {
        nreq,
        witnesses_per_row: w,
        quadratic_constraints_per_row: w,
        block_size: block,
        num_columns: block_enc,
        proof_size: sz,
    })
}

/// Run the C++ production optimizer (`circuits/mdoc/circuit_maker.cc:64`'s
/// `optimize` function): iterate candidate `block_enc ∈ [100, 2^17]`
/// over every integer (not just powers of two — the deprecated
/// `LigeroParam` constructor at `ligero_param.h:152` uses powers of two,
/// but the production tool that bakes `kZkSpecs[]` block_enc values
/// uses the integer range and produces the non-power-of-two values
/// (e.g. mdoc V6 num_attrs=2 hash circuit = 4025 = 5 * 5 * 7 * 23).
/// Mirror the production tool to maximize chance of byte-exact parity
/// with circuit binaries the C++ side ships.
fn optimize_block_enc(
    nw: usize,
    nq: usize,
    rate_inv: usize,
    nreq: usize,
    field_bytes: u64,
    field_subfield_bytes: u64,
    digest_bytes: u64,
    nonce_bytes: u64,
) -> Option<LayoutResult> {
    let mut best: Option<LayoutResult> = None;
    for e in 100..=(1usize << 17) {
        if let Some(layout) = ligero_layout(
            nw,
            nq,
            rate_inv,
            nreq,
            field_bytes,
            field_subfield_bytes,
            digest_bytes,
            nonce_bytes,
            e,
        ) {
            match &best {
                None => best = Some(layout),
                Some(prev) if layout.proof_size < prev.proof_size => best = Some(layout),
                _ => {}
            }
        }
    }
    best
}

/// Compute the Ligero parameters for an arbitrary circuit, picking
/// `block_enc` to minimize proof size — mirroring the deprecated
/// `LigeroParam(nw, nq, rateinv, nreq)` constructor in the C++ vendor.
///
/// `field_bytes` is the byte length of one field element; for example
/// 16 for `Field2_128` (= GF(2^128)) and 32 for `FieldP256`.
/// `field_subfield_bytes` is the byte length of the field's subfield
/// (2 for `Field2_128`, 32 for `FieldP256`).
///
/// `digest_bytes` and `nonce_bytes` are the SHA-256 digest length (32)
/// and merkle-nonce length (32) respectively. They're parameterized
/// for testability but always 32 for the production proof system.
pub fn default_ligero_params_for_circuit<FE: CodecFieldElement>(
    circuit: &Circuit<FE>,
    rate_inv: usize,
    nreq: usize,
    field_bytes: u64,
    field_subfield_bytes: u64,
) -> LigeroParameters {
    let layout = WitnessLayout::from_circuit(circuit);
    let nw = layout.length();
    let nq = circuit.num_layers();
    optimize_block_enc(
        nw,
        nq,
        rate_inv,
        nreq,
        field_bytes,
        field_subfield_bytes,
        /*digest_bytes=*/ 32,
        /*nonce_bytes=*/ 32,
    )
    .map(|r| LigeroParameters {
        nreq: r.nreq,
        witnesses_per_row: r.witnesses_per_row,
        quadratic_constraints_per_row: r.quadratic_constraints_per_row,
        block_size: r.block_size,
        num_columns: r.num_columns,
    })
    .expect("Ligero parameter optimization failed for this circuit shape")
}
