This folder holds the benchmark data and the scripts that produce it. The
pipeline is organized into three stages × five benchmark suites:

```
              run (and dump)        parse (to CSV)        plot
              ------------------    -------------------   -----------------
TT TPC-H      run_tt_tpch.sh        parse_tt_tpch.py      plot_tt_tpch.py
                                    parse_tt_commit.py    plot_commit.py
PGN compare   run_pgn.sh            parse_pgn.py          plot_pgn.py
micro         run_micro.sh          parse_micro.py        plot_micro*.py
baseline      run_baseline_tpch.sh  parse_baseline_tpch.py  (every TPC-H plot)
zkVM (SP1)    run_zkvm.sh           parse_zkvm_tpch.py      (every plot)
```

All scripts live in `tt-results/scripts/`. Each row is independent — you can
re-plot without re-running, or re-parse without re-plotting.

Per-suite outputs:

| Suite       | Raw files (`tt-results/raw/`)                | CSV (`tt-results/tidy/`) | Figures (`tt-results/figures/`) |
|-------------|----------------------------------------------|--------------------------|---------------------------------|
| TT TPC-H    | `benches_tt_*.json`, `bench_stats_tt_*.jsonl`, `benches_commit_*.json`, `commit_*.txt` | `tpch.csv`, `commit.csv` | `tpch_tt_*.pdf`, `commit_*.pdf` |
| PGN compare | `benches_pgn_*.json`, `bench_stats_pgn_*.jsonl`, `poneglyph_q*_k*.log`, `third_party_poneglyph_tpch.{log,json}` | `tpch_pgn.csv` | `tpch_pgn_*.pdf` |
| micro       | `third_party_*.log`, `third_party_*.json`, `zkvm_micro_cuda.*` | `micro.csv` | `micro*.pdf` |
| baseline    | `baseline_tpch_{1,4}.{log,json}`             | `tpch_baseline.csv`, `commit_baseline.csv` | all TPC-H and commit figures |
| zkVM (SP1)  | `zkvm_tpch_<pass>.*` | `tpch_zkvm.csv`, `commit_zkvm.csv` | all TPC-H and commit figures |

The Poneglyph comparison plots three systems side-by-side per query:
TruthTable on the `_pgn` query variants, PoneglyphDB on its KZG queries, and
the baseline. `run_pgn_fixed_tpch.sh` adds PoneglyphDB's data-independent
circuits, bound to the committed tables, as System "poneglyph
(data-independent)" in `tpch_pgn.csv`.

The baseline is a verifiable database with no proof system
(`third-party-bench/src/baseline.rs`): the commitment is a hash of every
column, the proof is the columns the query reads, and the verifier runs the
query itself. Every TPC-H and commit figure shows it next to TruthTable, on
the same queries over the tables without padding or system columns; it comes
from `run_baseline_tpch.sh`. `run_micro.sh` also runs it on the micro queries
(`third_party_baseline_{1,4}.*`), but those rows stay in `micro.csv`: the
micro figures leave the baseline out.

The SP1 zkVM (`third-party-bench/zkvm`) proves the TPC-H queries with
hand-written Rust in the zkVM, bound to SHA-256 column hashes, in two proof
modes: SP1's compressed proof and its Groth16 wrap. The TPC-H and commit
figures show its GPU prover (`run_zkvm.sh`); its CPU prover is not
benchmarked.

The micro figures compare TruthTable with PoSQL, QEDB, Poneglyph (its
data-independent micro circuits in the fork's `sql::micro_kzg`) and the SP1
zkVM, all on BN254, on the queries of `third-party-bench/src/micro.rs`; a
query a system cannot express is marked as not supported. `micro_prover_paper.pdf`
and `tpch_tt_combined.pdf` are drawn at the paper's text width with
print-size type (`scripts/paper_style.py`).

Panels with prover time or proof size use a log axis,
because the baseline's are milliseconds and megabytes. Prover-time panels also
show plain execution: the same query on the full tables, unverified.

## Running everything

```bash
./bench_all.sh
```

runs every suite, rebuilds every CSV, and renders every figure.
There are also stage-level helpers:

```bash
./tt-results/scripts/run_all.sh      # only run + dump
./tt-results/scripts/parse_all.sh    # only rebuild CSVs from existing raw files
./tt-results/scripts/plot_all.sh     # only render figures from existing CSVs
```

## Benchmarking one system

Timed runs need an idle machine. `run_micro.sh`, `run_pgn_fixed_tpch.sh`
and `run_baseline_tpch.sh` pin each CPU system to its thread count from CPU 0
up (one thread, or the baseline's four) and hide the GPU from it; only the
zkVM proves on the GPU. `run_tt_tpch.sh` and `run_pgn.sh` set the thread
count only, so start them under `taskset -c 0` for one-thread numbers.
Each script overwrites its raw files in `tt-results/raw/`, so move earlier
results aside before a partial rerun (for example one `MICRO_POWS` size).

| System | Micro queries | TPC-H |
|---|---|---|
| TruthTable | `MICRO_SYSTEMS=tt ./tt-results/scripts/run_micro.sh` | `./tt-results/scripts/run_tt_tpch.sh` (`_tt` queries and table commitments, SF 0.05 and 0.1, 1 and 4 threads); `PGN_SKIP_PONEGLYPH=1 ./tt-results/scripts/run_pgn.sh` (`_pgn` queries); `./tt-results/scripts/run_tt_tpch_optall.sh` (optimization ablation) |
| PoSQL | `MICRO_SYSTEMS=posql ./tt-results/scripts/run_micro.sh` | — |
| QEDB | `MICRO_SYSTEMS=qedb ./tt-results/scripts/run_micro.sh` | — |
| Poneglyph | `MICRO_SYSTEMS=poneglyph ./tt-results/scripts/run_micro.sh` (data-independent circuits; `PONEGLYPH_FAITHFUL=1` adds the original ones) | `./tt-results/scripts/run_pgn.sh` (original circuits, and TruthTable on the same queries); `./tt-results/scripts/run_pgn_fixed_tpch.sh` (data-independent circuits) |
| Baseline (no proof) | `MICRO_SYSTEMS=baseline ./tt-results/scripts/run_micro.sh` | `./tt-results/scripts/run_baseline_tpch.sh` |
| SP1 zkVM (GPU) | `MICRO_SYSTEMS=zkvm ./tt-results/scripts/run_micro.sh` | `./tt-results/scripts/run_zkvm.sh` |

`MICRO_SYSTEMS` takes several names (`"tt posql"`); without it `run_micro.sh`
runs every system. `MICRO_POWS` (comma-separated powers of two, default
15 to 20) and `MICRO_QUERIES` narrow the micro sweep for every system. The
zkVM and `run_pgn_fixed_tpch.sh` check results against DataFusion's, written
first by `(cd third-party-bench && cargo run --release --bin tpch_reference)`;
the zkVM's own prerequisites (SP1 toolchain, CUDA 12 runtime) are in
`third-party-bench/README.md`.

After a run, rebuild the suite's CSV and figures:

```bash
python3 tt-results/scripts/parse_micro.py      # micro → tidy/micro.csv
python3 tt-results/scripts/parse_tt_tpch.py    # TruthTable TPC-H → tidy/tpch.csv
python3 tt-results/scripts/parse_tt_commit.py  # TruthTable commitments → tidy/commit.csv
python3 tt-results/scripts/parse_pgn.py        # Poneglyph comparison → tidy/tpch_pgn.csv
python3 tt-results/scripts/parse_baseline_tpch.py
python3 tt-results/scripts/parse_zkvm_tpch.py
./tt-results/scripts/plot_all.sh               # every figure
```

## Running a single suite

```bash
# TT TPC-H (TruthTable on the regular TPC-H queries and its table
# commitments, multi-SF/threads matrix)
./tt-results/scripts/run_tt_tpch.sh
python3 tt-results/scripts/parse_tt_tpch.py
python3 tt-results/scripts/parse_tt_commit.py
python3 tt-results/scripts/plot_tt_tpch.py
python3 tt-results/scripts/plot_tt_tpch_combined.py
python3 tt-results/scripts/plot_commit.py

# Poneglyph comparison (TT-on-pgn + PoneglyphDB at matching dataset sizes)
./tt-results/scripts/run_pgn.sh
./tt-results/scripts/run_pgn_fixed_tpch.sh   # data-independent circuits
python3 tt-results/scripts/parse_pgn.py
python3 tt-results/scripts/plot_pgn.py

# Micro (every system on the queries of third-party-bench/src/micro.rs)
./tt-results/scripts/run_micro.sh
python3 tt-results/scripts/parse_micro.py
python3 tt-results/scripts/plot_micro.py            # micro.pdf, micro_setup.pdf
python3 tt-results/scripts/plot_micro_scaling.py    # prover, verifier and proof size against size
python3 tt-results/scripts/plot_micro_commit.py     # commitment time and size
python3 tt-results/scripts/plot_micro_prover_paper.py

# Baseline on TPC-H (the `_tt` and `_pgn` queries, 1 and 4 threads)
./tt-results/scripts/run_baseline_tpch.sh
python3 tt-results/scripts/parse_baseline_tpch.py
./tt-results/scripts/plot_all.sh
```

## Plot prerequisites

The plot scripts need Python 3.12 with `matplotlib`, `numpy`, `pandas`. Use
the pinned env:

```bash
cd tt-results
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`.python-version` pins the interpreter if you use pyenv.

## Streamlit bench dashboard

For interactive exploration of `raw/bench_stats.jsonl`:

```bash
cd tt-results
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r dashboard_requirements.txt
streamlit run bench_dashboard.py
```
