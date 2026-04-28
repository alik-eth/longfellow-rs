# `crates/longfellow/tests/fixtures/`

Static byte fixtures co-located with the longfellow crate's integration
tests. Used by:

* `tests/fixtures.rs` — smoke-load tests (this task, #74).
* `tests/p7s_zk_parser.rs` — synthetic v12 blob parser tests (#71).
* `xtask/parity-longfellow/` (#75) — Rust↔C++ parity driver.

## Layout

```
fixtures/
├── README.md                              ← this file
└── p7s/
    ├── testanchor-a-binding-v12.qkb.p7s   ← v12 anchor-A synthetic
    ├── testanchor-b-binding.qkb.p7s       ← v11 anchor-B synthetic
    ├── testanchor-b-admin-binding.qkb.p7s ← v11 anchor-B admin variant
    ├── binding.qkb.p7s                    ← v11 DIIA real signer
    ├── admin-binding.qkb.p7s              ← v11 DIIA admin variant
    ├── kat-subject-serial.json            ← X.520 serialNumber KAT JSON
    └── reference/
        ├── czo-test-testsigner.p7s        ← CZO QTSP reference signer
        └── hu-microsec-mic-1.p7s          ← Hungarian Microsec reference
```

mdoc circuit-binary + proof fixtures are NOT duplicated under
`fixtures/`; they're already at `crates/longfellow/test-vectors/mdoc_zk/`
(ISRG's original release layout). `tests/fixtures.rs` references them
directly to exercise the real `Circuit::decode` path against all 8 V6/V7
circuit binaries (zstd-compressed → decompress → decode signature
circuit (FieldP256) → decode hash circuit (Field2_128)).

```
crates/longfellow/test-vectors/mdoc_zk/      (referenced in-place — not duplicated)
├── 6_1_137e5a75…                            ← V6, 1 attribute
├── 6_2_b4bb6f01…                            ← V6, 2 attributes
├── 6_3_b2211223…                            ← V6, 3 attributes
├── 6_4_c70b5f44…                            ← V6, 4 attributes
├── 7_1_8d079211…                            ← V7, 1 attribute
├── 7_2_6a581068…                            ← V7, 2 attributes
├── 7_3_8ee4849a…                            ← V7, 3 attributes
├── 7_4_5aebdaaa…                            ← V7, 4 attributes
├── v6_1attr_issue_date.proof                ← V6 1-attr proof bytes
├── v7_1attr_issue_date.proof                ← V7 1-attr proof bytes
└── v6_v7_1attr_issue_date.json              ← witness + public-input metadata
```

## What's NOT here (and why)

### mdoc workspace `v11/v12` fixtures

The workspace's `crates/zk-eidas-mdoc/` has no `fixtures/` directory and
no static on-disk byte fixtures. mdoc test data used by host-side code
is constructed in-memory from the V6/V7 circuit-binary fixtures above
plus runtime-built witnesses. "v11/v12" in this workspace's vocabulary
refer to the *p7s blob schema versions*, not mdoc — orthogonal axis.

### v12 *blob-byte* fixtures (the format `parse_witness_blob` /
### `parse_public_blob` consume)

The `.qkb.p7s` files in this directory are **raw CAdES-BES CMS
SignedData documents** — the upstream input to v12 blob construction.
The `parse_witness_blob` / `parse_public_blob` functions in
`crates/longfellow/src/p7s_zk/parser.rs` consume v12 *blob* bytes
(4-byte schema + parsed structure with `cert_tbs` + offsets +
`holder_seed_commit` + `holder_seed`). Producing those blobs from a
`.qkb.p7s` requires running
`crates/zk-eidas-p7s::build_witness(qkb_bytes, context, root_pk,
holder_seed)` — i.e. the existing host pipeline that constructs
witnesses at test runtime.

Static blob-byte fixtures will land alongside #95 (the `build_witness`
Rust port). Tracked in #97. See the project task list.

### Pre-compiled p7s circuit bytes

The C++ p7s circuit is built in-process at proof-generation time and
never serialized to disk. So there's no `.bin` / `.circuit.zst` to
bundle here. Phase 4's SP1 wrap will require capturing these bytes via
the C++ build-time tool; that's out of scope for #74.

## Per-fixture provenance

### `testanchor-a-binding-v12.qkb.p7s` (1718 B)

**v12 synthetic fixture under TestAnchorA root.** Produced by
`cargo run --bin gen_v12_fixture` (see
`crates/zk-eidas-p7s/src/bin/gen_v12_fixture.rs`). Deterministic —
running the generator twice produces byte-identical output.

Pinned values:
* `holder_seed = [0x42; 32]` — matches the demo-api test seed.
* `stable_id = b"TINUA-1234567890"` — DIIA RNOKPP shape.
* `context = b"0x"` — matches existing demo-api `b"0x"` tests.
* Root key derived from seed `b"zk-eidas-test-anchor-A-root-v1"` —
  byte-identical to the vendor circuit's compile-time
  `kTrustAnchors[0]`.

Used by `crates/zk-eidas-p7s/tests/fixture_test_anchor_a_v12.rs`
upstream.

### `testanchor-b-binding.qkb.p7s` (15,969 B) and `testanchor-b-admin-binding.qkb.p7s` (15,970 B)

**TestAnchorB synthetic fixtures**, pre-v12 schema. Different signer
chain (anchored under `kTrustAnchors[1]`), used to exercise the N=2
trust-anchor mux added in vendor task #44.

### `binding.qkb.p7s` (15,969 B) and `admin-binding.qkb.p7s` (15,970 B)

**Real DIIA QTSP fixtures** captured from a production Diia binding
flow. Use the production DIIA root certificate; pre-v12 schema.

`admin-binding.qkb.p7s` is the same flow with an admin attribute
asserted in the binding JSON.

### `kat-subject-serial.json` (varies)

KAT test vector documenting the 9-byte X.520 serialNumber DER anchor
used by invariant 7 (the stable-ID extraction). Static reference data
mirrored from `crates/zk-eidas-p7s/fixtures/kat-subject-serial.json`.

### `reference/czo-test-testsigner.p7s` (8152 B)

**Czech QTSP reference signer** for cross-QTSP testing. Pre-v12.

### `reference/hu-microsec-mic-1.p7s` (13,494 B)

**Hungarian Microsec QTSP reference signer** for cross-QTSP testing.
Pre-v12.

## Update protocol

If you regenerate any `*-v12.qkb.p7s` from
`gen_v12_fixture.rs`, copy the output here AND update the
`zk-eidas-p7s/fixtures/` source-of-truth — the two must stay in sync.
The `gen_v12_fixture` generator is deterministic, so the only valid
trigger for an update is a schema-version bump or a pinned-seed
change, both of which are spec-level events.

The reference QTSP signers are external artifacts; they get updated
only when the QTSPs themselves re-issue.
