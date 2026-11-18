# Third-party benchmark harness

This directory compares TruthTable against two other verifiable-SQL systems and
a no-proof baseline on the same set of microbenchmark queries and the same
table shapes:

| System | Crate path used | What we measure |
|---|---|---|
| **TruthTable** (this repo) | `crates/tt-exec` | prover time, verifier time, proof size |
| **sxt-proof-of-sql** | `../../sxt-proof-of-sql` | same |
| **qedb** | `../../qedb` | same |
| **Baseline** | `benches/baseline.rs` | commit time, commitment size, prover time, verifier time, proof size |

The baseline has no proof system. The commitment is a BLAKE3 hash of every
column (Arrow IPC encoding) plus the schema and row count, in a `.colhash`
file. The prover plans the query and sends every column its table scans read;
the verifier hashes them against the commitment and runs the query itself with
DataFusion. It queries the raw parquets (`bench_table_<pow>.parquet`, not the
`_preprocessed` ones TruthTable commits to), so there is no padding or
activator column. Each phase is the median of five runs, in fractional
milliseconds. The bench also times plain execution, the query on the full
tables with no verification at all (`execute_ms`), and checks the verifier's
result against it. It reads the Join_PK_FK parquets the truth_table bench
writes, so run that bench first.

The protocol lives in [src/baseline.rs](src/baseline.rs). `benches/baseline.rs`
runs it on the micro queries above; `benches/baseline_tpch.rs` runs it on the
TPC-H `_tt` and `_pgn` queries at SF 0.01–0.1, generating its own tables under
`artifact/tpch/` (driven by `tt-results/scripts/run_baseline_tpch.sh`).

### zkVM (SP1)

[zkvm/](zkvm/) proves the micro queries and the TPC-H `_tt` and `_pgn`
queries in the SP1 zkVM. It is a Cargo
workspace of its own: the guest (`zkvm/program`) is built for SP1's RISC-V
target with SP1's toolchain, and `sp1-sdk` pins its own dependency versions.

- Commit: the data owner publishes the SHA-256 hash of every column, in the
  flat layout of `zkvm/lib` (type tag, row count, little-endian values).
- Prove: the guest reads the encoded columns the query needs, hashes them with
  SP1's SHA-256 accelerator, runs a hand-written Rust version of the query
  (`zkvm/lib/src/tpch.rs` for TPC-H) and commits the query, the input hashes
  and the hash of the result. Each run is proved twice: SP1's compressed
  proof, and the same wrapped in Groth16 (`ZKVM_MODES`).
- Verify: check the proof, compare the input hashes with the published ones,
  and hash the result handed over separately.

Prerequisites: `curl -L https://sp1up.succinct.xyz | bash && sp1up`. The GPU
prover downloads `sp1-gpu-server` into `~/.sp1/bin` on first use; it links
the CUDA 12 runtime, so on a CUDA 13 machine extract `libcudart.so.12` from
NVIDIA's `nvidia-cuda-runtime-cu12` wheel into `~/.sp1/lib/cuda12`.
The Groth16 wrap downloads SP1's circuit files (about 8 GB) into
`~/.sp1/circuits` on first use.

The TPC-H binary checks every query's result against DataFusion's before
proving it; write those results first with
`cargo run --release --bin tpch_reference -- <sf>...` (from this directory).
`tt-results/scripts/run_zkvm.sh` runs the passes (`ZKVM_PASSES`, e.g.
`"cpu:1 cpu:4 cuda"`) and writes `tt-results/raw/third_party_zkvm_<pass>.*`
(micro) and `zkvm_tpch_<pass>.*` (TPC-H). The CPU prover takes about 44x the
GPU's time and, with SP1's default worker counts, over 100 GB of memory.

The benches use the same auto-generated Parquet tables under
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
2. For each bench (`sxt_proof_of_sql`, `qedb`, `truth_table`, `baseline`), runs
   `cargo bench --bench <name>` with `RAYON_NUM_THREADS` pinned (see below)
   and tees the log to `tt-results/raw/third_party_<bench>.log`.
3. Parses each log into `tt-results/raw/third_party_<bench>.json` via
   [`parse_bench_output.py`](parse_bench_output.py).

The baseline runs once per thread count in `BASELINE_THREADS` (1 and 4),
pinned to CPUs `0..t-1`, and writes `third_party_baseline_<t>.{log,json}`.
`MICRO_ONLY_BASELINE=1` runs only the baseline passes. Its `micro.csv` rows
have curve `none` and also fill `commit time (s)` and `commitment size (KB)`;
the micro figures do not plot them.

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
  `benches/sxt_proof_of_sql.rs`, `benches/qedb.rs`, `benches/truth_table.rs`
  and `benches/baseline.rs`. Keep them in sync.
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
