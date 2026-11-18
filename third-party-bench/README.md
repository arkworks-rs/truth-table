# Third-party benchmark harness

This directory compares TruthTable against three other verifiable-SQL
systems, the SP1 zkVM and a no-proof baseline on the same micro-benchmark
queries over the same tables. The commands that run each system, on the
micro queries and on TPC-H, are listed in
[tt-results/readme.md](../tt-results/readme.md#benchmarking-one-system).

| System | Source | What we measure |
|---|---|---|
| **TruthTable** (this repo) | `crates/tt-exec` | prover time, verifier time, proof size |
| **Proof of SQL** | `alireza-shirzad/sxt-proof-of-sql`: upstream plus the benchmark crate | same |
| **QEDB** | `alireza-shirzad/qedb-primitives`: upstream `ProvablyAI/qedb-primitives` plus a `bn254` feature | same, plus commit time |
| **Poneglyph** | `alireza-shirzad/PoneglyphDB`: the micro queries as circuits (`sql::micro_kzg`) | prover time, verifier time, proof size, key generation |
| **SP1 zkVM** | [zkvm/](zkvm/): the queries as Rust programs proved by SP1 on the GPU | same, compressed and Groth16-wrapped |
| **Baseline** | `benches/baseline.rs` | commit time, commitment size, prover time, verifier time, proof size |

## Micro queries

[src/micro.rs](src/micro.rs) holds the queries and their tables. A table is a
pure function of its name and size, so every bench builds the same rows:
TruthTable and the baseline read the parquet files it writes under
`artifact/micro/size_<pow>/<query>/`, PoSQL builds its tables through its
column override, and QEDB builds them in memory.

| Query | SQL | PoSQL | QEDB | Poneglyph |
|---|---|---|---|---|
| `filter_0p1`, `filter_1`, `filter_10` | `SELECT a, b, c, d … WHERE a = 1 AND b = 2`, selecting 0.1%, 1% and 10% of the rows | ✓ | ✓ | ✓ |
| `aggregate` | `SELECT SUM(a), COUNT(*) … WHERE b = 1` (10% of the rows) | ✓ | ✓ | ✓ |
| `range` | `SELECT a, b … WHERE a >= 100 AND a <= 199` (about 10%) | ✓ | ✓ | ✓ |
| `in_list` | `SELECT a, b, c, d … WHERE a IN (16 values)` (about 1%) | ✓ | ✓ | ✓ |
| `arithmetic` | `SELECT SUM(a * b) … WHERE c = 1` | ✓ | ✗ | ✓ |
| `group_by` | `SELECT b, SUM(a), COUNT(*) … GROUP BY b` (100 groups) | ✓ | ✗ | ✓ |
| `join_pk_fk` | `… WHERE l.a = r.a`, `l.a` a primary key and `r.a` a foreign key into it | ✓ | ✗ | ✓ |
| `join_m2m` | the same join with keys repeated on both sides (about as many output rows as input) | ✓ | ✗ | ✓ |
| `order_by` | `SELECT a, b … ORDER BY a LIMIT 10` | ✗ | ✗ | ✓ |

Each table has 2^15 to 2^20 rows (`MICRO_POWS`); a join's two tables have
that many each.
PoSQL cannot express ORDER BY; QEDB has no arithmetic, grouping or join test.
Poneglyph has no SQL front end either: each micro query is a circuit in the
fork's `sql::micro_kzg`, built from Poneglyph's gadgets (`IsZeroChip`,
`LtEqGenericChip`, `PermAnyChip`) and the gate patterns of its TPC-H circuits
(Q1's grouping, Q3's join). Every query has two variants; the bench runs
the fixed one, and both with `PONEGLYPH_FAITHFUL=1`:

- *faithful*: as in those circuits, the witness enables the selectors of kept,
  output and group-end rows, so the verifying key depends on the data, and
  nothing ties those selectors to the predicate: whoever generates the keys
  can leave a passing row out of the result. All six benchmarked TPC-H
  circuits (Q1, Q3, Q5, Q8, Q9, Q18) work this way.
- *fixed* ("Poneglyph (data-independent)" in `micro.csv`): every selector
  covers a range fixed by the table size; which rows pass, where groups end
  and which rows join are witness flags, and the flagged shuffles force the
  output to hold exactly the passing rows. The tables are the circuit's
  first advice columns, committed without blinding, so the proof is bound
  to the data owner's commitments to them (`commit_ms`). The PK/FK join is
  the paper's §4.4 protocol; a many-to-many join has no sound fixed-size
  circuit, so `join_m2m` has no fixed variant.

The six TPC-H circuits are rebuilt the same way in the fork's
`sql::fixed_tpch` and `sql::q1_fixed_kzg`. [benches/poneglyph_tpch.rs](benches/poneglyph_tpch.rs)
runs them on the `_pgn` queries over the `_poneglyph` tables, after checking
each circuit's result against DataFusion's (`tpch_reference`), and
`tt-results/scripts/run_pgn_fixed_tpch.sh` runs the sweep on one thread.

QEDB's library has no SQL front end: [benches/qedb.rs](benches/qedb.rs) builds
each query from its tests the way its own benchmark does.

Every system runs on BN254: TruthTable by default, PoSQL with HyperKZG,
Poneglyph with halo2's KZG, and QEDB through the fork's `bn254` feature. Upstream QEDB is BLS12-381 only, but
its tests use the curve only through arkworks' generic traits, so the fork
re-exports the curve from one module; its test suite passes on both curves.

The baseline has no proof system. The commitment is a BLAKE3 hash of every
column (Arrow IPC encoding) plus the schema and row count, in a `.colhash`
file. The prover plans the query and sends every column its table scans read;
the verifier hashes them against the commitment and runs the query itself with
DataFusion. It queries the raw parquets (not the `_preprocessed` ones
TruthTable commits to), so there is no padding or activator column. Each phase is the median of five runs, in fractional
milliseconds. The bench also times plain execution, the query on the full
tables with no verification at all (`execute_ms`), and checks the verifier's
result against it.

The protocol lives in [src/baseline.rs](src/baseline.rs). `benches/baseline.rs`
runs it on the micro queries above; `benches/baseline_tpch.rs` runs it on the
TPC-H `_tt` and `_pgn` queries at SF 0.01–0.1, generating its own tables under
`artifact/tpch/` (driven by `tt-results/scripts/run_baseline_tpch.sh`).

### zkVM (SP1)

[zkvm/](zkvm/) proves the micro queries (`zkvm/lib/src/micro.rs`, reading
the parquet files `micro_data` writes) and the TPC-H `_tt` and `_pgn`
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
`tt-results/scripts/run_zkvm.sh` runs it on the GPU and writes
`tt-results/raw/zkvm_tpch_cuda.*`; it resumes from its log after an
interruption. The CPU prover is not benchmarked: on 4 threads it takes about
100x the GPU's time and 37–58 GB of memory.

## Prerequisites

PoSQL, QEDB and Poneglyph are **git dependencies** pinned by commit in
`Cargo.toml`, each from the `main` branch of a fork: PoSQL from
`alireza-shirzad/sxt-proof-of-sql` (upstream `spaceandtimefdn/sxt-proof-of-sql`
plus the `proof-of-sql-benchlib` crate), QEDB from
`alireza-shirzad/qedb-primitives`, Poneglyph from `alireza-shirzad/PoneglyphDB`,
whose halo2 is patched to `alireza-shirzad/halo2_PSE` (unblinded advice
columns). Cargo fetches them under `~/.cargo/git/`. To bump one, update its
`rev` in [Cargo.toml](Cargo.toml) and run `cargo update -p <crate>`. With the
`posql-blitzar` feature PoSQL's runner links `libblitzar`, which `cargo bench`
puts on the library path; a bench binary run directly then needs
`LD_LIBRARY_PATH` set to the `blitzar-sys` build output.

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
./tt-results/scripts/run_micro.sh          # every system → raw/*.{log,json}
python3 tt-results/scripts/parse_micro.py  # → tt-results/tidy/micro.csv
./tt-results/scripts/plot_all.sh           # → figures/micro*.pdf among the rest
```

`run_micro.sh` builds every bench, writes every table's parquet file
(`cargo run --bin micro_data`), then runs TruthTable, PoSQL, QEDB and Poneglyph
on one thread pinned to CPU 0, the baseline on 1 and 4 threads (CPUs 0..t-1),
and the SP1 zkVM on the GPU (`run_zkvm.sh`, suite `micro`). `MICRO_SYSTEMS`
(`tt posql qedb poneglyph baseline zkvm`) picks systems, `MICRO_POWS` (default
15 to 20) and `MICRO_QUERIES` narrow the sweep. Each system's log and JSON go
to `tt-results/raw/`; a failure in one system does not stop the others.

Every prover runs once; every verifier repeats for up to a second and reports
the median. What each system measures:

| Metric | TruthTable | PoSQL | QEDB | Poneglyph | zkVM |
|---|---|---|---|---|---|
| setup | its keys, per key size | HyperKZG setup | the reference string | KZG parameters per degree | the program keys |
| proving key | `.pk` file | the prover setup | the reference string | halo2 proving key (and the parameters, separately) | not exposed on the GPU |
| verifying key | `.vk` file | the verifier setup | `VerifierKey` | halo2 verifying key | `SP1VerifyingKey` |
| key generation | — | — | — | per circuit, after setup | — |
| table commitment | padding the table, then committing it | column commitments | column and index handles | none: the tables are witnesses | SHA-256 of each column |
| proof | proof file | `QueryProof` | the tests' proofs | halo2 proof | compressed, and Groth16 |

TruthTable's keys are never smaller than 2^16: a query can open a 16-variable
polynomial whatever the table size.

## Configuring what runs

- **Table sizes**: `MICRO_POWS` (comma-separated powers of two, default
  15 to 20), read by every bench and the zkVM.
- **Queries**: `MICRO_QUERIES` (comma-separated names, default all); the list
  is `QUERIES` in [src/micro.rs](src/micro.rs).

## Output layout

After a full run:

```
third-party-bench/artifact/micro/       # tables, TruthTable's keys and proofs
tt-results/raw/third_party_<bench>.log  # raw stdout per bench
tt-results/raw/third_party_<bench>.json # parsed, structured results
tt-results/tidy/micro.csv               # unified long-form table
tt-results/figures/micro.pdf                    # every system at the largest size
tt-results/figures/micro_setup.pdf              # setup, key sizes, commitments
tt-results/figures/micro_{prover,verifier,proof_size}_scaling.pdf  # against size, per query
tt-results/figures/micro_commit_{time,size}.pdf # the data owner's commitment
tt-results/figures/micro_prover_paper.pdf       # the paper's prover figure
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
