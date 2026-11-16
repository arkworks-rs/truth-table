#!/usr/bin/env python3
"""
Rebuild the baseline TPC-H CSVs from the outputs of run_baseline_tpch.sh.

Reads:
  raw/baseline_tpch_1.json, raw/baseline_tpch_4.json

Writes:
  tidy/tpch_baseline.csv   — one row per (Q, variant, SF); variant is `tt`
                             (the `_tt` queries) or `pgn` (the `_pgn` ones)
  tidy/commit_baseline.csv — one row per (table, SF)

The baseline verifier runs the query itself, so its time is reported per
thread count, like the prover's.

Usage:
  python3 tt-results/scripts/parse_baseline_tpch.py
"""

import csv
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR.parent / "raw"
TIDY_DIR = SCRIPT_DIR.parent / "tidy"
THREADS = ["1", "4"]

TPCH_HEADER = [
    "Q", "variant", "scale-factor",
    "prover time 1thread (s)", "prover time 4threads (s)",
    "verifier time 1thread (ms)", "verifier time 4threads (ms)",
    "proof size (KB)", "result rows",
]
COMMIT_HEADER = [
    "table", "scale-factor",
    "latency-1thread(ms)", "latency-4thread(ms)", "size(KB)",
]


def fmt(value, decimals):
    s = f"{value:.{decimals}f}"
    return s.rstrip("0").rstrip(".") if "." in s else s


def main():
    queries = {}
    tables = {}
    for t in THREADS:
        path = RAW_DIR / f"baseline_tpch_{t}.json"
        if not path.exists():
            print(f"  missing {path.name}; its columns stay empty")
            continue
        data = json.loads(path.read_text())
        suffix = "1thread" if t == "1" else "4threads"
        for r in data["results"]:
            row = queries.setdefault((r["q"], r["variant"], r["sf"]), {})
            row[f"prover time {suffix} (s)"] = fmt(r["prove_ms"] / 1000, 7)
            row[f"verifier time {suffix} (ms)"] = fmt(r["verify_ms"], 4)
            row["proof size (KB)"] = fmt(r["proof_bytes"] / 1024, 3)
            row["result rows"] = str(r["result_rows"])
        for r in data["tables"]:
            row = tables.setdefault((r["name"], r["sf"]), {})
            row[f"latency-{t}thread(ms)"] = fmt(r["commit_ms"], 4)
            row["size(KB)"] = fmt(r["commitment_bytes"] / 1024, 3)

    if not queries and not tables:
        print(f"No baseline TPC-H JSON found in {RAW_DIR}; nothing to do.")
        return

    TIDY_DIR.mkdir(parents=True, exist_ok=True)
    tpch_path = TIDY_DIR / "tpch_baseline.csv"
    with open(tpch_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(TPCH_HEADER)
        for (q, variant, sf), row in sorted(
            queries.items(), key=lambda kv: (kv[0][1], float(kv[0][2]), kv[0][0])
        ):
            w.writerow([f"q{q}", variant, sf] + [row.get(c, "") for c in TPCH_HEADER[3:]])
    commit_path = TIDY_DIR / "commit_baseline.csv"
    with open(commit_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(COMMIT_HEADER)
        for (name, sf), row in sorted(tables.items(), key=lambda kv: (float(kv[0][1]), kv[0][0])):
            w.writerow([name, sf] + [row.get(c, "") for c in COMMIT_HEADER[2:]])
    print(f"Wrote {tpch_path}: {len(queries)} rows; {commit_path}: {len(tables)} rows")


if __name__ == "__main__":
    main()
