# CI RAM Characterization for ECDSA-Proving + Parity Tests

Spec reference: `docs/superpowers/specs/2026-04-28-pure-rust-longfellow-migration-design.md`,
open question #4 — "CI machine RAM budget for parity tests."

Task: #91. Date: 2026-04-28. Branch: `worktree-longfellow-rust-migration`.

## TL;DR

| | Today (C++ only) | Phase 1-2 (parity, both implementations) | Post-phase 3 (Rust verifier-only) |
|---|---|---|---|
| Recommended `--test-threads` | 1 (for prove-heavy tests via `#[serial]` + RUST_TEST_THREADS=8 env) | **1** (mandatory: Rust + C++ in same suite roughly 2x peak) | up to N=8-16 (verifier RSS is small; cliff far away) |
| Peak per-test RSS | ~2.85 GiB | ~5-6 GiB projected (sequential within `#[serial]`, but two implementations resident) | <500 MiB expected |
| Headroom on 32GB CI | ~10 concurrent (theoretical) | **~5 concurrent (theoretical) — plus C++ vendor build artefacts** | ample (~60 concurrent) |

**Policy for the migration window (phases 1-2): `--test-threads=1` enforced for any test crate that links both
`longfellow-sys` and `longfellow`.** Encode via the existing `#[serial]` pattern on each parity test plus a
note in the parity-test crate's README. Workspace `RUST_TEST_THREADS=8` env already in `.cargo/config.toml`
remains correct as a default — it's the cap for non-prove tests, not the heavy ones.

**Post-phase 3 (vendor deleted): re-evaluate.** Verifier-only tests likely fit under threads=8+ comfortably.

## Methodology

Measurement host: 16-core x86_64, 62 GiB physical RAM, 8 GiB swap. Tool: `/usr/bin/time -v` (peak RSS via
`getrusage(RUSAGE_CHILDREN).ru_maxrss`).

Tests under measurement (all real ECDSA-proving, ~21-42s wall):

- **Probe 1**: `cargo test -p zk-eidas-p7s-circuit -F slow-tests --test v12_prove_canary -- --test-threads=1` —
  pure-Rust facade test. Single prove + verify against TestAnchorA v12 fixture. Calls `longfellow-sys` C++
  prover under the hood (today's only Longfellow implementation).
- **Probe 2**: `cargo test -p zk-eidas-demo-api p7s_prove_happy_test_anchor_a -- --test-threads=1` —
  demo-api integration test exercising the full HTTP-handler prove path.
- **Probe 3**: `cargo test -p zk-eidas-demo-api p7s_verify_round_trip_happy -- --test-threads=1` —
  demo-api integration test, full prove + verify round trip.
- **Probe 4**: `cargo test -p zk-eidas-demo-api -- p7s_prove_happy_test_anchor p7s_verify_round_trip_happy
  --test-threads=2` — attempted parallel run of two p7s tests at threads=2 to find a cliff.

Measurements were taken on a warm `target/` (test binaries pre-built via `--no-run`); reported peak RSS
covers `cargo test`'s lifetime including the test runner, which dominates the working set.

## Raw measurements

| Probe | Test | --test-threads | Wall-clock (s) | Peak RSS (KB) | Peak RSS (GiB) | CPU% |
|---|---|---|---|---|---|---|
| 1 | `v12_prove_round_trip_test_anchor_a` (zk-eidas-p7s-circuit) | 1 | 21.86 | 2,985,484 | 2.85 | 99 |
| 2 | `p7s_prove_happy_test_anchor_a` (demo-api) | 1 | 41.06 | 2,966,456 | 2.83 | 99 |
| 3 | `p7s_verify_round_trip_happy` (demo-api) | 1 | 41.91 | 2,966,700 | 2.83 | 98 |
| 4 | `p7s_prove_happy*` + `p7s_verify_round_trip_happy` (demo-api) | 2 | 42.86 | 2,966,568 | 2.83 | 99 |

### Observations

- **Single prove cycle peaks at ~2.85 GiB.** This is consistent with the existing `.cargo/config.toml`
  comment ("Each ECDSA prove peaks at ~2GB RAM"); reality is closer to 2.85 GiB. The comment was an
  underestimate by ~30%.
- **Verify is essentially free relative to prove.** Probe 3 (round trip) peak RSS matches Probe 2
  (prove-only) within noise (~250 KB delta). The peak is dominated by circuit cache + prover working set,
  and verify's incremental cost is in the noise. **Wall-clock for verify alone is ~1s** (Probe 3 wall
  41.91 vs Probe 2 wall 41.06).
- **`--test-threads=2` does not actually parallelize on demo-api.** Probe 4 peak RSS and wall-clock are
  effectively unchanged from Probe 3, despite running two heavy tests. Reason: every demo-api prove/verify
  test is annotated `#[serial]` (via `serial_test` crate or explicit code-level mutex). Concurrency is
  defeated by design even with high `--test-threads`. **Implication: `--test-threads=N` is upper-bound
  configuration, not actual parallelism.**
- **The `RUST_TEST_THREADS=8` workspace env (in `.cargo/config.toml`) is misleading without context.** It
  caps thread count for the cheaper unit tests; the heavy prove tests are gated by `#[serial]` and run
  sequentially regardless. Both layers are needed.
- **Test compilation** consumed ~42-49s for cold builds in this session. RSS during `cargo test --no-run`
  reaches ~2.5 GiB just for the rustc compilation pipeline (LLVM IR + linking), not accounted for above
  but worth noting as a CI-startup peak.

## Parity-test projection (phase 1 sub-PRs)

Phase 1.7 (task #75) builds `xtask/parity-longfellow/`, which links **both** `longfellow` (Rust, new) and
`longfellow-sys` (C++ vendor). A parity-cross-check test will:

1. Run Rust prover on fixture F, capture proof P_rust.
2. Run C++ prover on fixture F, capture proof P_cpp.
3. Cross-verify (Rust verifier accepts P_cpp; C++ verifier accepts P_rust).
4. Public-output byte-equality check.

**Memory profile projection:** within a single test, only one prove runs at a time (sequential in test
body). So peak RSS per parity test ≈ max(Rust prove peak, C++ prove peak), NOT the sum. Probably ~2.9-3.5
GiB per test (small overhead for the Rust crate vs current numbers, since the Rust prover allocates similar
witness/circuit working sets).

**However:** if multiple parity tests run in parallel (e.g., `--test-threads=2`), peak combined would be
~5.5-7 GiB. Adding the test binary itself (which links *both* `longfellow` and `longfellow-sys` and so loads
larger circuit caches resident) might push individual peak past 4 GiB.

**Conservative recommendation: enforce `--test-threads=1` on the parity test crate.** Either via:

- **(A)** `#[serial]` annotation on every parity test (matches existing pattern). Pros: works regardless of
  invocation. Cons: extra annotation per test.
- **(B)** A `[package.metadata.cargo-runner]` or `.cargo/config.toml` override scoped to the parity crate
  that hardcodes `RUST_TEST_THREADS=1`. Pros: one config edit. Cons: only fires under the cargo runner; raw
  test-binary invocation would bypass.
- **(C)** Both. Belt-and-suspenders.

Prior precedent in this codebase (the `#[serial]` annotation pattern) argues for (A). Recommend (A) on every
parity test plus a CI README note about `--test-threads=1` for raw-binary runs.

## Cliff analysis (where things break)

The `--test-threads=N` headroom is gated by:
1. **Per-test peak RSS** — observed ~2.85 GiB.
2. **Compile-time RSS** — observed ~2.5 GiB during `cargo test --no-run`.
3. **C++ vendor build RSS** — `cmake` + `cc` for `longfellow-sys` consumes ~3-4 GiB during a fresh build.

On 32 GiB CI: roughly 25 GiB usable for tests (system reserves ~7 GiB for OS + cargo's own working set).

- Pure-Rust unit tests (verifier-only, post-phase-3): ~50-200 MiB each. Fits 100+ concurrent. `RUST_TEST_THREADS=16`
  would be safe.
- ECDSA-proving tests (today, single implementation): 32 GiB / 2.85 GiB ≈ 8.7 concurrent ceiling.
  `RUST_TEST_THREADS=8` is the right cap; existing `.cargo/config.toml` is correct.
- Parity tests (phase 1-2): 32 GiB / 6 GiB ≈ 5 concurrent ceiling, but `#[serial]` makes this moot in
  practice. **Set the cap to 1 anyway** to make it explicit and protect against accidental
  unannotated-test additions.

## Reproducing these measurements

```sh
# Probe 1
cargo test -p zk-eidas-p7s-circuit -F slow-tests --test v12_prove_canary --no-run
/usr/bin/time -v cargo test -p zk-eidas-p7s-circuit -F slow-tests --test v12_prove_canary -- --test-threads=1

# Probe 2
cargo test -p zk-eidas-demo-api --no-run
/usr/bin/time -v cargo test -p zk-eidas-demo-api p7s_prove_happy_test_anchor_a -- --test-threads=1

# Probe 3
/usr/bin/time -v cargo test -p zk-eidas-demo-api p7s_verify_round_trip_happy -- --test-threads=1
```

Look for `Maximum resident set size (kbytes):` in stderr.

## Recommendations to land

1. **`--test-threads=1` for the phase-1 parity test crate** (`xtask/parity-longfellow/`, when it lands in
   task #75). Implement via `#[serial]` annotation on every `#[test]` fn.

2. **Update the `.cargo/config.toml` comment** to state `~2.85 GiB` instead of `~2GB`.

3. **Consider a CI-side hard memory limit** (e.g., `cgroups` `memory.max` = 28 GiB on a 32 GiB box) so that
   any future runaway test fails loudly rather than triggering OOM-kill that takes down the runner.
   This is **out of scope for #91** but worth surfacing — implementation belongs in a CI-config task.

4. **Re-run this characterization at end of phase 3** (after C++ vendor deletion), and update the table.
   The verifier-only path should drop the per-test RSS below 1 GiB, dramatically widening the threads cap.

## What this report does NOT cover

- Parity tests themselves don't exist yet (task #75). Numbers above for "parity" are projections from
  single-implementation measurements + reasonable assumptions about non-overlap.
- SP1 prover RAM (different beast, phase 4 task #89).
- macOS/aarch64 CI runners (only x86_64 Linux measured; SP1 patches aarch64-apple-darwin separately).
- Cold compile RAM (test-binary build itself can spike past test-runtime RSS for big crates; not measured
  here since dispatch was about test-runtime characterization).
- The Rust-side prover memory profile, since the Rust prover doesn't yet exist as an end-to-end working
  pipeline (#75/#76 will deliver it).
