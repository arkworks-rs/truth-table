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
- Renamed the rematerialize operation to **compaction**, matching the paper (#32): `RematerializeLogicalNode` → `CompactionLogicalNode`, `RematerializeRule` → `CompactionRule`, `RematerializeCheck` → `CompactionCheck`, modules `plan::rematerialize{,_dpuc}` → `plan::compaction{,_dpuc}` and `utils::remat` → `utils::compaction`, cost-model terms `remat*` → `compaction*`. The single-column `Defragmenter` is now `Compactor`. The `tpch_optall` bench IDs keep their `remat_on` / `remat_off` suffix so recorded results still parse.

- Keyed sums are proved by ark-piop's protocol. `irs::nodes::utils::keyed_sumcheck::piop` is now an adapter onto `ArgProver::add_mv_keyed_sum_claim`, and the two local copies of the helper-commitment protocol (the PIOP and the one inline in the keyed-sumcheck gadget node) are gone. Every keyed sum and lookup of a proof is discharged in one batch when the proof is built; under ark-piop's default LogUp-GKR that removes a commitment per column (TPC-H at scale 0.05: prover time 611 s → 379 s single-threaded, proofs 15–44% larger). `ARK_PIOP_LOOKUP_PROTOCOL=logup` keeps the committed helpers.
- Refitted the LIKE cost model (`crates/tt-arithmetic/cost_model.toml`) to the prover as it is after the keyed sums moved to ark-piop: 51 single-threaded proofs on `l_comment`, kept in `crates/tt-fingerprint-optimizer/results/cost-points-l_comment.csv` (RMS error 6.7 s over proofs of 74–569 s). The model is now in single-threaded seconds; the one it replaces was fitted to multi-threaded proofs of an earlier prover. Of the 29 benchmark queries the prover's bin choice changes for six; two of them (`%n%t%`, `%o%n%`) now get a pre-filter and prove 1.22× and 1.24× faster.
- Removed `crates/tt-fingerprint-optimizer/docs/fingerprint-optimization.tex` and the fingerprint benchmark's recorded proof timings and figures (`results/bench-proofs-l_comment.csv` and seven plots), which were taken on an earlier prover. The benchmark's inputs, the commit timings and the cost model's points stay.

### Fixed
- Proving the same query over the same data now gives the same proof and the same result every time. Two things made the order of rows depend on scheduling: DataFusion sessions were built with the default of one partition per core, whose batches are merged in arrival order, and the match-pair gadget collected the union of its two inputs the same way. Every session is now built by `tt_core::session::session_context()` with one partition, and the union is read one input after the other. Under the command-line tool TPC-H Q2 used to give 8 different proofs in 96 runs, and an aggregate or a join without `ORDER BY` a different result order on nearly every run.
- The proof-size stats (`proof_size.crypto.breakdown` in `bench_stats.jsonl`) left out the LogUp-GKR subproofs, the lookup messages and the labelled field vectors, so the parts did not add up to the proof; under LogUp-GKR the missing part is most of it (35 KB of TPC-H Q6's 53 KB). All three are reported now, and so is the `constants` part of each PCS subproof.
- CI workflow was pinned to `nightly-2025-04-03` while `rust-toolchain.toml` pins `stable`; aligned CI to `dtolnay/rust-toolchain@stable` so CI matches local builds. Split into two paths modeled on ark-piop's structure: a strict per-check job suite (fmt / clippy / test / bench compile) gated on PRs to main, and a single fast job (fmt + check + production-targets clippy + lib tests) gated on pushes to any non-main branch. The old conditional was subtly wrong — `github.ref == 'refs/heads/main'` only fires on direct pushes to main, so PRs-to-main previously ran the fast path instead of the strict one.
- Join PK/FK verifier bug where prover and verifier disagreed on the `__row_id__` materialization flag in partial-materialization joins, causing tracker IDs to desync and the verifier to reject valid proofs.
- `rematerialize.rs` round-tripped `LogicalPlan::Join` through `plan.with_new_exprs(plan.expressions(), ...)`, which silently flattened join `ON` pairs. Added `expressions_for_with_new_exprs` to preserve the binary-expression shape.
- Removed 187 MB of stray debug logs and a ~750 KB debug-dump binary from the repo root; `.gitignore` now catches them.

### Removed
- The `tt-col-toolbox` crate. Its lookup and keyed-sumcheck PIOPs moved into `tt-core` next to the gadgets that wrap them (`irs::nodes::utils::lookup::piop`, `irs::nodes::utils::keyed_sumcheck::piop`); the duplicate keyed-sumcheck copy under `nodup/` and the unused `fold_check`, compactor, and bag-split helpers are gone.
- Stale commented-out `mod` declarations in `tt-core/src/lib.rs` and `tt-exec/src/lib.rs` (the on-disk `tt-core/src/test_display.rs` and `tt-exec/src/data_owner/` files are left in place since they contain substantial WIP code — delete when intentionally obsolete).
- Dead `GadgetAncestry` struct that was exported but never constructed anywhere.

## Past iterations

This is the first public changelog entry. Prior development happened on a private branch; commit history is preserved in the Git log.
