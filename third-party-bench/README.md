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

The three comparison systems are pulled as **git dependencies** pinned by
commit SHA in `Cargo.toml`:

```toml
[patch.crates-io]
ark-piop              = { git = "https://github.com/alireza-shirzad/ark-piop", rev = "…" }

[dependencies]
proof-of-sql-benchlib = { git = "https://github.com/Pratyush/sxt-proof-of-sql", rev = "…" }
proof-of-sql          = { git = "https://github.com/Pratyush/sxt-proof-of-sql", rev = "…" }
qedb                  = { git = "https://github.com/alireza-shirzad/qedb", rev = "…" }
```

No sibling checkouts are needed — cargo fetches and caches the three repos
under `~/.cargo/git/`. To bump any of them, update the `rev = …` in
[Cargo.toml](Cargo.toml) and run `cargo update -p <crate>`.

The harness also applies a local `arrow-arith` patch (`patches/arrow-arith-51.0.0`)
via `[patch.crates-io]`; this is for an sxt-proof-of-sql compatibility fix, not
TruthTable itself.

Python reporting prerequisites (for the CSV + figure steps):

```bash
pip install -r ../tt-results/requirements.txt
```

## Running the full sweep

The micro-benchmark suite is wired into the unified pipeline under
[tt-results/scripts/](../tt-results/scripts/). From the repo root:

```bash
./tt-results/scripts/run_micro.sh        # cargo bench + parse to per-bench JSON
python3 tt-results/scripts/parse_micro.py  # JSONs → tt-results/tidy/micro.csv
python3 tt-results/scripts/plot_micro.py   # micro.csv → figures/micro_*.pdf
```

Or run everything (micro + TT TPC-H + Poneglyph comparison) end-to-end with
`./bench_all.sh`.

What `run_micro.sh` does:

1. Wipes `artifact/Join/` and `artifact/Join_PK_FK/` so stale join parquets
   don't leak across runs (other sizes are reused — they're independent of the
   PK/FK shape).
2. For each bench (`sxt_proof_of_sql`, `qedb`, `truth_table`), runs
   `cargo bench --bench <name>` with `RAYON_NUM_THREADS` pinned (see below)
   and tees the log to `tt-results/raw/third_party_<bench>.log`.
3. Parses each log into `tt-results/raw/third_party_<bench>.json` via
   [`parse_bench_output.py`](parse_bench_output.py).

Failures in one bench don't abort the others.

## Thread pinning

`NUM_THREADS` at the top of `tt-results/scripts/run_micro.sh` (default `1`) is
propagated as both `RAYON_NUM_THREADS` (consumed by Rayon) and
`TT_BENCH_NUM_THREADS` (stamped into the JSON output by the parser). The two
must match — otherwise the `num_threads` column in `micro.csv` lies about
what was actually measured.

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

- **`failed to load source for dependency … from git`**: network or auth
  problem reaching one of the pinned forks. Verify the URLs/rev in
  [Cargo.toml](Cargo.toml) and that you can reach github.com. To work from a
  local checkout instead, edit Cargo.toml to use `path = "../../<repo>"` and
  delete `Cargo.lock`.
- **`micro.csv` shows `num_threads=<wrong>`**: `RAYON_NUM_THREADS` was set
  outside the script. Always drive via `run_micro.sh` so both env vars stay
  in lockstep.
- **Plots look empty or stale**: rerun just the reporting steps —
  `python3 tt-results/scripts/parse_micro.py && python3 tt-results/scripts/plot_micro.py`.
  The benches don't need to rerun.
- **Only one bench failed**: its log is at
  `tt-results/raw/third_party_<bench>.log`. The others' JSON is still good and
  `micro.csv` will reflect whichever benches produced output.
