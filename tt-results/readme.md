This folder holds the benchmark data and the scripts that produce it. The
pipeline is organized into three stages × three benchmark suites:

```
              run (and dump)        parse (to CSV)        plot
              ------------------    -------------------   -----------------
TT TPC-H      run_tt_tpch.sh        parse_tt_tpch.py      plot_tt_tpch.py
PGN compare   run_pgn.sh            parse_pgn.py          plot_pgn.py
micro         run_micro.sh          parse_micro.py        plot_micro.py
```

All scripts live in `tt-results/scripts/`. Each row is independent — you can
re-plot without re-running, or re-parse without re-plotting.

Per-suite outputs:

| Suite       | Raw files (`tt-results/raw/`)                | CSV (`tt-results/tidy/`) | Figures (`tt-results/figures/`) |
|-------------|----------------------------------------------|--------------------------|---------------------------------|
| TT TPC-H    | `benches_tt_*.json`, `bench_stats_tt_*.jsonl`| `tpch.csv`               | `tpch_tt_*.pdf`                 |
| PGN compare | `benches_pgn_*.json`, `bench_stats_pgn_*.jsonl`, `poneglyph_q*_k*.log` | `tpch_pgn.csv` | `tpch_pgn_*.pdf` |
| micro       | `third_party_*.log`, `third_party_*.json`    | `micro.csv`              | `micro_*.pdf`                   |

The Poneglyph comparison plots two systems side-by-side per query:
TruthTable on the `_pgn` query variants, and PoneglyphDB on its KZG queries.

## Running everything

```bash
./bench_all.sh
```

runs all three suites, rebuilds all three CSVs, and renders every figure.
There are also stage-level helpers:

```bash
./tt-results/scripts/run_all.sh      # only run + dump
./tt-results/scripts/parse_all.sh    # only rebuild CSVs from existing raw files
./tt-results/scripts/plot_all.sh     # only render figures from existing CSVs
```

## Running a single suite

```bash
# TT TPC-H (TruthTable on the regular TPC-H queries, multi-SF/threads matrix)
./tt-results/scripts/run_tt_tpch.sh
python3 tt-results/scripts/parse_tt_tpch.py
python3 tt-results/scripts/plot_tt_tpch.py

# Poneglyph comparison (TT-on-pgn + PoneglyphDB at matching dataset sizes)
./tt-results/scripts/run_pgn.sh
python3 tt-results/scripts/parse_pgn.py
python3 tt-results/scripts/plot_pgn.py

# Micro (PoSQL / QEDB / TT on Filter / Aggregate / Join / Join PK/FK / Limit)
./tt-results/scripts/run_micro.sh
python3 tt-results/scripts/parse_micro.py
python3 tt-results/scripts/plot_micro.py
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
