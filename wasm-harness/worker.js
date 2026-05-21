// p7s v12 prover Web Worker.
//
// Runs the (synchronous, ~50s) wasm prove off the main thread, then
// verifies the proof it just produced — a full in-browser cryptographic
// round trip. The page stays responsive throughout; the worker posts the
// proof + measurements back.
import init, {
  p7s_prove_v12_fixture,
  p7s_verify_v12_fixture,
  wasm_memory_bytes,
} from './pkg/longfellow.js';

// Kick off wasm instantiation as soon as the worker module loads.
const ready = init();

self.onmessage = async (e) => {
  if (e.data !== 'prove') return;
  try {
    await ready;
    const memInitBytes = wasm_memory_bytes();

    // 1. Prove (blocks THIS worker thread only).
    const t0 = performance.now();
    const proof = p7s_prove_v12_fixture();
    const t1 = performance.now();

    // 2. Verify the proof we just produced.
    let verified = false;
    let verifyError = null;
    try {
      p7s_verify_v12_fixture(proof); // throws on rejection
      verified = true;
    } catch (err) {
      verifyError = String((err && err.message) || err);
    }
    const t2 = performance.now();
    const peakBytes = wasm_memory_bytes();

    // Transfer the proof buffer (zero-copy) back to the page. Must come
    // after verify — transferring detaches the underlying ArrayBuffer.
    self.postMessage(
      {
        ok: true,
        proofLen: proof.length,
        proveMs: t1 - t0,
        verifyMs: t2 - t1,
        verified,
        verifyError,
        memInitBytes,
        peakBytes,
        proof,
      },
      [proof.buffer],
    );
  } catch (err) {
    self.postMessage({ ok: false, error: String((err && err.stack) || err) });
  }
};
