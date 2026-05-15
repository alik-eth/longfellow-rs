# p7s v12 WASM prover — browser harness

A minimal browser harness proving that the pure-Rust Longfellow **p7s v12
prover** runs in a real browser, off the main thread, via a Web Worker.

Measured (Chrome 148, headless): peak **1.137 GiB** wasm linear memory,
**~48s** wall, main thread stays fully responsive (the on-page liveness
counter ticks uninterrupted through the prove).

## Files

- `worker.js` — module Web Worker; loads the wasm, runs the synchronous
  `p7s_prove_v12_fixture()` prove off-thread, posts proof + measurements back.
- `index.html` — spawns the worker; a 100 ms main-thread timer proves the
  page never blocks during the ~48s prove.

The wasm-bindgen surface used (`p7s_prove_v12_fixture`, `wasm_memory_bytes`)
lives in `crates/longfellow/src/js_api.rs` under `feature = "wasm"`.

## Build + run

```sh
# from the longfellow crate dir; getrandom needs the wasm_js backend
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' \
  wasm-pack build . --target web --release --out-name longfellow \
  --out-dir wasm-harness/pkg -- --features wasm

cd wasm-harness && python3 -m http.server 8765
# open http://localhost:8765/index.html
```

`pkg/` is generated build output — not committed.

## Notes

- This is a measurement / proof-of-feasibility harness, not a production
  integration. A production path would pass the holder's real
  witness/public blobs into the worker (the fixture is embedded here for a
  self-contained test) and surface progress in the UI.
- Mobile browsers cap wasm memory well below 1.14 GiB — desktop only.
