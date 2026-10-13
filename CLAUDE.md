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

## Comments and docs
- A comment says what the code cannot: why it is this way, an invariant, a
  soundness condition, a constraint that lives elsewhere. If deleting it
  loses the reader nothing, delete it.
- Do not restate the name, the signature or the next line (`/// Returns the
  id.` on `fn id()`, `// Track the commitment` above `track_commitment(..)`).
  A `pub` item needs a doc only when the doc adds to its name.
- One to three lines by default. A longer block is for an algorithm, a
  protocol or a data layout: the statement, the steps, what soundness needs.
  Say each thing once; an item's doc does not repeat its module's doc, and a
  module doc does not list what its items already say.
- No history. What the code used to do, the bug that led to it, how it was
  found, commit hashes, PR numbers, dates, measurements from one run and
  words like "now", "no longer", "previously" belong in the commit message.
  State the present rule and its reason.
- No status notes ("currently wired", "step 4d is done"), no references to
  context the reader does not have ("the fix above", "as discussed"), no
  section banners, no commented-out code.
- The paper is context the reader has: cite it by section or protocol number
  instead of re-deriving it.

## Helper functions
Extract a function only when one of these holds:
1. it is a meaningful logical block used in more than one place;
2. it is used once, but it is a meaningful logical block and naming it makes
   the caller easier to read.

Otherwise keep the code inline. In particular, do not add a function that
only forwards to another one, that wraps one expression, that exists to
shorten its caller without being a step a reader would name, or that takes
most of its caller's locals as parameters.

## Conventions
- No debugging or profiling code left in the repo.
- Do not touch `paper.pdf` or `tt-results/` unless asked.
- The operation that repacks active rows onto a smaller domain is called
  **compaction**, as in the paper (eprint 2026/1260). Do not reintroduce
  "rematerialize", "remat" or "defrag". The one exception is the `tpch_optall`
  bench IDs (`..._remat_on` / `..._remat_off`): they are the keys of the
  recorded results in `tt-results/`. "Materialize" is a different operation.
- Build every DataFusion session with `tt_core::session::session_context()`,
  never `SessionContext::new()`. The default runs a plan in one partition per
  core and merges them in arrival order, which makes row order, and so the
  proof, differ from run to run. A `UNION` has a partition per input even so:
  collect it with `collect_partitioned`, not `collect`.
- There is no column-toolbox crate. A raw PIOP lives in a `piop` module next
  to the gadget node that wraps it (`irs/nodes/utils/<name>/piop/`); reuse the
  existing one instead of copying it.
