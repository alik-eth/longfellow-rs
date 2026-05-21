//! WASM memory-peak measurement harness for the p7s v13 prover
//! (variable-length serialNumber, Task #37).
//!
//! Runs one full `P7sZkProver::prove` over the TestAnchorA fixture and
//! reports the peak wasm linear-memory size. wasm linear memory only ever
//! grows (`memory.grow` never shrinks), so the size observed after the
//! prove completes is the high-water mark for the whole run.
//!
//! v13 re-measure (2026-05-21): peak 1.241 GiB via the Node WASI path —
//! unchanged from v12; the wider 46-byte serialNumber window adds no
//! meaningful memory.
//!
//! Build + run:
//! ```sh
//! cargo build --release --target wasm32-wasip1 -p longfellow \
//!     --example wasm_p7s_mem --features prover
//! node --experimental-wasi-unstable-preview1 \
//!     crates/longfellow/wasm-harness/wasm_mem_run.mjs
//! ```
//!
//! This is a scratch measurement tool, not part of the library surface.

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("wasm_p7s_mem is a wasm32-only measurement harness; build with --target wasm32-wasip1");
}

#[cfg(target_arch = "wasm32")]
fn main() {
    use longfellow::{
        Codec,
        circuit::Circuit,
        circuit_data::p7s_circuit_v12_decompressed,
        fields::{CodecFieldElement, field2_128::Field2_128, fieldp256::FieldP256},
        io::Cursor,
        p7s_zk::{P7S_NREQ, P7S_RATE_INV, P7sZkProver, default_ligero_params_for_circuit},
    };

    const WITNESS: &[u8] =
        include_bytes!("../tests/fixtures/p7s/blobs/testanchor_a_v12_witness.bin");
    const PUBLIC: &[u8] =
        include_bytes!("../tests/fixtures/p7s/blobs/testanchor_a_v12_public.bin");

    const PAGE: u64 = 65536;
    let mem = || core::arch::wasm32::memory_size(0) as u64 * PAGE;

    let m_start = mem();

    // Decompress + decode the embedded circuit (ruzstd path).
    let circuit_bytes = p7s_circuit_v12_decompressed();
    let m_circuit = mem();

    let mut cursor = Cursor::new(circuit_bytes);
    let hash_circuit = Circuit::<Field2_128>::decode(&mut cursor).expect("hash circuit decode");
    let sig_circuit = Circuit::<FieldP256>::decode(&mut cursor).expect("sig circuit decode");

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

    let prover = P7sZkProver::new(circuit_bytes, hash_params, sig_params)
        .expect("P7sZkProver::new");
    let m_prover_ready = mem();

    let proof = prover.prove(WITNESS, PUBLIC).expect("prove");
    let m_peak = mem();

    let gib = |b: u64| b as f64 / 1_073_741_824.0;
    println!("proof_len_bytes={}", proof.len());
    println!("mem_start_bytes={} ({:.3} GiB)", m_start, gib(m_start));
    println!("mem_after_circuit_bytes={} ({:.3} GiB)", m_circuit, gib(m_circuit));
    println!(
        "mem_after_prover_new_bytes={} ({:.3} GiB)",
        m_prover_ready,
        gib(m_prover_ready)
    );
    println!("peak_wasm_memory_bytes={} ({:.3} GiB)", m_peak, gib(m_peak));
}
