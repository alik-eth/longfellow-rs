// Error type surfaced by the mdoc_zk wasm bindings (`src/js_api.rs`).
//
// Re-created from upstream: `UPSTREAM.md` records the upstream `js/` stub
// was not imported, which left `#[wasm_bindgen(module = "/js/error.js")]`
// pointing at a missing file — any `--features wasm` build's glue failed
// to load. This restores the stub.
export class MdocZkError extends Error {
  constructor(message) {
    super(message);
    this.name = "MdocZkError";
  }
}
