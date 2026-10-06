# truth-table

## Build and dependencies
- `Cargo.toml` patches `ark-piop` to `../ark-piop`. Keep a checkout of
  github.com/alireza-shirzad/ark-piop next to this repo. CI clones its
  `master` there, so an ark-piop fix only reaches CI once it is pushed.
- `Cargo.lock` is not tracked. CI uses the current stable toolchain, which can
  be newer than the local one; a lint that passes locally can fail in CI.

## Tests
- `just test` and CI run unit tests only. The end-to-end prove-and-verify
  tests are behind a feature:
  `cargo test --release -p tt-exec --features test-utils` (about 4 minutes).
  Run them after any change to gadgets, planning, tracking or ark-piop.
- `--features honest-prover` makes the prover check each claim and name the
  gadget that fails. If it names nothing and verification still fails, the
  prover and verifier built different statements; compare the two sides.
- The full end-to-end suite with `honest-prover` is far heavier than without:
  the `filter` suite alone ran past 38 minutes and 46 GB. For a quick check
  run the small tables only, e.g.
  `cargo test --release -p tt-exec --features test-utils,honest-prover --test filter nation`.
- `tt-fp-measure` and `tt-fp-calibrate` need `--features calibration`. A plain
  build leaves stale binaries in `target/release`.

## Benchmarks
- Timed runs are single-threaded on an idle machine:
  `RAYON_NUM_THREADS=1 taskset -c 0`. No builds or other heavy jobs meanwhile.
- The fingerprint benchmark is
  `crates/tt-fingerprint-optimizer/scripts/bench_single_thread.sh <outdir>`
  (resumable, about three days); plots come from `scripts/plot_bench.py`.
- Figures show speed-up over no pre-filter, not seconds.

## Conventions
- No debugging or profiling code left in the repo.
- Do not touch `paper.pdf` or `tt-results/` unless asked.
- The operation that repacks active rows onto a smaller domain is called
  **compaction**, as in the paper (eprint 2026/1260). Do not reintroduce
  "rematerialize", "remat" or "defrag". The one exception is the `tpch_optall`
  bench IDs (`..._remat_on` / `..._remat_off`): they are the keys of the
  recorded results in `tt-results/`. "Materialize" is a different operation.
- There is no column-toolbox crate. A raw PIOP lives in a `piop` module next
  to the gadget node that wraps it (`irs/nodes/utils/<name>/piop/`); reuse the
  existing one instead of copying it.
