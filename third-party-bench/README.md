# Third-party benchmark harness

This directory compares TruthTable against two other verifiable-SQL systems on
the same set of microbenchmark queries and the same table shapes:

| System | Crate path used | What we measure |
|---|---|---|
| **TruthTable** (this repo) | `crates/tt-exec` | prover time, verifier time, proof size |
| **sxt-proof-of-sql** | `../../sxt-proof-of-sql` | same |
| **qedb** | `../../qedb` | same |

The three benches use the same auto-generated Parquet tables under
`artifact/size_<pow>/`, so "same inputs, different provers" is a real apples-to-apples
comparison rather than three systems reading unrelated data. The Join / Join_PK_FK
parquets in particular share a deterministic PK/FK row layout written by the
sxt bench and read by the other two.

## Prerequisites

The three systems are **sibling checkouts**, not submodules. Clone them next to
this repo:

```
<parent>/
├── truth-table/            ← you are here
├── sxt-proof-of-sql/
└── qedb/
```

`Cargo.toml` references them by relative path:

```toml
proof-of-sql-benchlib = { path = "../../sxt-proof-of-sql/crates/proof-of-sql-benchlib" }
proof-of-sql          = { path = "../../sxt-proof-of-sql/crates/proof-of-sql" }
qedb                  = { path = "../../qedb" }
```

Missing either sibling repo will fail the build with a `path dependency not found`
error — clone them first.

The harness also applies a local `arrow-arith` patch (`patches/arrow-arith-51.0.0`)
via `[patch.crates-io]`; this is for an sxt-proof-of-sql compatibility fix, not
TruthTable itself.

Python reporting prerequisites (for the CSV + figure steps):

```bash
pip install -r ../tt-results/requirements.txt
```

## Running the full sweep

From the repo root:

```bash
./third-party-bench/run_all.sh
```

The script does four things:

1. Wipes `artifact/Join/` and `artifact/Join_PK_FK/` so stale join parquets
   don't leak across runs (other sizes are reused — they're independent of the
   PK/FK shape).
2. For each bench (`sxt_proof_of_sql`, `qedb`, `truth_table`), runs
   `cargo bench --bench <name>` with `RAYON_NUM_THREADS` pinned (see below)
   and tees the log to `tt-results/raw/third_party_<bench>.log`.
3. Parses each log into `tt-results/raw/third_party_<bench>.json` via
   [`parse_bench_output.py`](parse_bench_output.py).
4. Regenerates `tt-results/tidy/micro.csv` and the
   `tt-results/figures/micro_*.pdf` plots.

Failures in one bench don't abort the others — `run_all.sh` runs with
`set -uo pipefail` (no `-e`) deliberately.

## Thread pinning

`NUM_THREADS` at the top of `run_all.sh` (default `1`) is propagated as both
`RAYON_NUM_THREADS` (consumed by Rayon) and `TT_BENCH_NUM_THREADS` (stamped
into the JSON output by the parser). The two must match — otherwise the
`num_threads` column in `micro.csv` lies about what was actually measured.

The paper numbers were taken with `NUM_THREADS=1`. To re-measure at a
different thread count, edit the variable and rerun.

## Configuring what runs

- **Table sizes**: `TABLE_POWS = &[16, 17, 18, 19]` near the top of each of
  `benches/sxt_proof_of_sql.rs`, `benches/qedb.rs`, and `benches/truth_table.rs`.
  Keep all three in sync.
- **Iterations**: `BENCH_ITERS` in `benches/sxt_proof_of_sql.rs` (the other two
  benches report a single wall-clock sample per `(query, size)` pair).
- **Queries**: the `QUERIES` slice in each bench. Filter, Aggregate, Limit,
  Join, and Join_PK_FK are intentionally the same SQL across all three systems.

## Output layout

After a full run:

```
third-party-bench/artifact/             # cached Parquet + intermediate artifacts
tt-results/raw/third_party_<bench>.log  # raw stdout per bench
tt-results/raw/third_party_<bench>.json # parsed, structured results
tt-results/tidy/micro.csv               # unified long-form table
tt-results/figures/micro_prover_time.pdf
tt-results/figures/micro_verifier_time.pdf
tt-results/figures/micro_proof_size.pdf
```

`artifact/` can be deleted to force a full regeneration (and will add ~minutes
per size on the next run).

## Troubleshooting

- **`path dependency … not found`**: you don't have `sxt-proof-of-sql` or
  `qedb` cloned beside `truth-table`. See [Prerequisites](#prerequisites).
- **`micro.csv` shows `num_threads=<wrong>`**: `RAYON_NUM_THREADS` was set
  outside the script. Always drive via `run_all.sh` so both env vars stay in
  lockstep.
- **Plots look empty or stale**: rerun just the reporting steps —
  `python3 tt-results/update_micro_csv.py && python3 tt-results/tt-scripts/plot_micro.py`.
  The benches don't need to rerun.
- **Only one bench failed**: its log is at
  `tt-results/raw/third_party_<bench>.log`. The others' JSON is still good and
  `micro.csv` will reflect whichever benches produced output.
