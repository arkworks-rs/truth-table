# Changelog

All notable changes to TruthTable are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/) once a stable release is cut.

## [Unreleased]

### Added
- PolyForm Noncommercial 1.0.0 license — free for academic / research / personal use; commercial use requires a separate license.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` covering governance and security reporting.
- `crates/tt-exec/examples/quickstart.rs` — one-command end-to-end prove / verify on auto-generated TPC-H data, reachable via `cargo run --release -p tt-exec --example quickstart`.
- README **Quick start** section driving the new example, plus **Publishing** section in `CONTRIBUTING.md` explaining the `[patch.crates-io]` blocker.
- Crate-level `//!` documentation on `tt-core`, `tt-exec`, `tt-proof-planner`, and `tt-tpch-data` summarizing each crate's role, plus module-level and key-type docs across the `tt-core/irs` public surface (`Tree`, `Ir`, `LocalPass`, `PassOrder`, `Node`, `PlanNode`, `PayloadStructure`, `EmptyPayload`, and the `shared_ir` stage aliases).
- GitHub issue templates (bug / feature / security contact link) and a pull-request template under `.github/`.
- `third-party-bench/README.md` documenting prerequisites (sibling `sxt-proof-of-sql` and `qedb` checkouts), how to run `run_all.sh`, output layout, and thread-pinning caveats.
- README CI / license badges at the top.
- MSM wrapper with a naive / Pippenger threshold and thread-count table at `ark-piop/src/arithmetic/msm.rs` (unused; available as an opt-in API with a `calibrate_msm` example binary).
- Workspace-wide `[workspace.lints.rust] warnings = "deny"` gate; all member crates inherit via `[lints] workspace = true`.

### Changed
- Lifted shared package metadata (`version`, `edition`, `license`, `repository`, `homepage`, `authors`) into `[workspace.package]` and switched every member crate to inherit via `*.workspace = true`. Every crate now has a `description` populated too. Incidentally bumped `tt-arithmetic` from edition 2021 to 2024 so the workspace has a single edition.
- Co-located each plan node's gadget with its plan definition: `tt-core/src/irs/nodes/plan/<kind>/<name>/gadget/` replaces the old `tt-core/src/irs/nodes/gadget/**` tree. Utility gadgets live at `tt-core/src/irs/nodes/utils/`.
- Third-party bench harness now runs all three systems (truth_table, sxt_proof_of_sql, qedb) on the same PK/FK-shaped join tables, and pins `RAYON_NUM_THREADS` to match the stamped thread-count in the JSON output.
- `run_all.sh` now regenerates `tt-results/tidy/micro.csv` and all three `micro_*.pdf` figures automatically after benches complete.

### Fixed
- CI workflow was pinned to `nightly-2025-04-03` while `rust-toolchain.toml` pins `stable`; aligned CI to `dtolnay/rust-toolchain@stable` so CI matches local builds. Split into two paths modeled on ark-piop's structure: a strict per-check job suite (fmt / clippy / test / bench compile) gated on PRs to main, and a single fast job (fmt + check + production-targets clippy + lib tests) gated on pushes to any non-main branch. The old conditional was subtly wrong — `github.ref == 'refs/heads/main'` only fires on direct pushes to main, so PRs-to-main previously ran the fast path instead of the strict one.
- Join PK/FK verifier bug where prover and verifier disagreed on the `__row_id__` materialization flag in partial-materialization joins, causing tracker IDs to desync and the verifier to reject valid proofs.
- `rematerialize.rs` round-tripped `LogicalPlan::Join` through `plan.with_new_exprs(plan.expressions(), ...)`, which silently flattened join `ON` pairs. Added `expressions_for_with_new_exprs` to preserve the binary-expression shape.
- Removed 187 MB of stray debug logs and a ~750 KB debug-dump binary from the repo root; `.gitignore` now catches them.

### Removed
- Stale commented-out `mod` declarations in `tt-core/src/lib.rs` and `tt-exec/src/lib.rs` (the on-disk `tt-core/src/test_display.rs` and `tt-exec/src/data_owner/` files are left in place since they contain substantial WIP code — delete when intentionally obsolete).
- Dead `GadgetAncestry` struct that was exported but never constructed anywhere.

## Past iterations

This is the first public changelog entry. Prior development happened on a private branch; commit history is preserved in the Git log.
