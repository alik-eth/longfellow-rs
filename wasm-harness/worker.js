// p7s v12 prover Web Worker.
//
// Runs the (synchronous, ~50s) wasm prove off the main thread. The page
// stays fully responsive; the worker posts the proof + measurements back.
import init, { p7s_prove_v12_fixture, wasm_memory_bytes } from './pkg/longfellow.js';

// Kick off wasm instantiation as soon as the worker module loads.
const ready = init();

self.onmessage = async (e) => {
  if (e.data !== 'prove') return;
  try {
    await ready;
    const memInitBytes = wasm_memory_bytes();
    const t0 = performance.now();
    const proof = p7s_prove_v12_fixture(); // blocks THIS worker thread only
    const t1 = performance.now();
    const peakBytes = wasm_memory_bytes();
    // Transfer the proof buffer (zero-copy) back to the page.
    self.postMessage(
      { ok: true, proofLen: proof.length, wallMs: t1 - t0, memInitBytes, peakBytes, proof },
      [proof.buffer],
    );
  } catch (err) {
    self.postMessage({ ok: false, error: String((err && err.stack) || err) });
  }
};
