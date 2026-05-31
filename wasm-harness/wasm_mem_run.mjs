// Node WASI runner for the wasm32-wasip1 memory-measurement harness.
//
// Executes the p7s wasm prover (built from `examples/wasm_p7s_mem.rs`)
// under Node's WASI and lets the module print its own peak wasm
// linear-memory size.
//
//   cargo build --release --target wasm32-wasip1 -p longfellow \
//       --example wasm_p7s_mem --features prover
//   node --experimental-wasi-unstable-preview1 \
//       crates/longfellow/wasm-harness/wasm_mem_run.mjs
import { WASI } from 'node:wasi';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Standalone repo: wasm-harness/ -> crate root, then target/.
// (Was ../../../target in the zk-eidas monorepo; this crate is now its own repo.)
import { existsSync } from 'node:fs';
const here = dirname(fileURLToPath(import.meta.url));
const rel = 'target/wasm32-wasip1/release/examples/wasm_p7s_mem.wasm';
// Prefer the standalone layout (one level up); fall back to the old monorepo
// layout (three levels up) so the harness works in either checkout.
const wasmPath = [join(here, '..', rel), join(here, '../../..', rel)].find(
  existsSync,
) ?? join(here, '..', rel);

const wasi = new WASI({ version: 'preview1', args: ['wasm_p7s_mem'], env: {} });

const t0 = Date.now();
const wasm = await WebAssembly.compile(await readFile(wasmPath));
const instance = await WebAssembly.instantiate(wasm, wasi.getImportObject());
try {
  wasi.start(instance);
} catch (e) {
  console.error('wasm run error:', e);
  process.exitCode = 1;
}
console.error(`wall_clock_seconds=${((Date.now() - t0) / 1000).toFixed(1)}`);
