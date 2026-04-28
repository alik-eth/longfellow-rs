# Upstream provenance

This crate is a hard fork of [`abetterinternet/zk-cred-longfellow`](https://github.com/abetterinternet/zk-cred-longfellow),
the ISRG pure-Rust port of the Longfellow ZK system.

## Pinned import

| Field        | Value                                                    |
|--------------|----------------------------------------------------------|
| Upstream     | `https://github.com/abetterinternet/zk-cred-longfellow`  |
| Pinned SHA   | `b1e37001efa4ef3821389ac6ec2ccc6e2dae885f`               |
| HEAD subject | `Fix Clippy lint (#217)`                                 |
| Imported on  | 2026-04-28                                               |

## Fork policy

We own this code from the import commit forward. There is no upstream tracking
or rebase obligation. Bug fixes from upstream may be cherry-picked selectively
post-migration (see spec
`docs/superpowers/specs/2026-04-28-pure-rust-longfellow-migration-design.md`).

## What was imported

- `src/` — full source tree
- `benches/` — criterion benchmarks
- `test-vectors/` — KAT data used by `cargo test -p longfellow`
- `LICENSE` (MPL-2.0)
- `README.md`, `CONTRIBUTING.md`, `deny.toml` (informational)

## What was *not* imported

- `xtask/` — upstream's HTTP demo crate, unrelated to our migration's xtask
- `fuzz/` — separate cargo-fuzz nested workspace, deferred
- `js/` — single-file error stub, unused
- `.github/`, `.cargo/`, `.gitignore`, `Cargo.lock` — workspace already owns these

## Local edits to the imported `Cargo.toml`

- Removed the `[workspace]` block (we live inside the `zk-eidas` workspace).
- Renamed `package.name` from `zk-cred-longfellow` to `longfellow`.

No source edits. No feature gating. No v12 patches. These land in subsequent
phase 1 sub-PRs (tasks #69 onward).
