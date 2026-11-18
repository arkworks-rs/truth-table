#!/usr/bin/env python3
"""
Rebuild the zkVM (SP1) TPC-H CSVs from the outputs of run_zkvm.sh.

Reads:
  raw/zkvm_tpch_cuda.json

Writes:
  tidy/tpch_zkvm.csv   — one row per (Q, variant, SF, prover, mode); variant
                         `tt` or `pgn`, prover `gpu`, mode
                         `compressed` or `groth16`
  tidy/commit_zkvm.csv — one row per (table, SF): the data owner's SHA-256
                         column hashes

proof size (KB) is the saved proof the verifier loads; raw proof (B) is the
Groth16 proof alone.

Usage:
  python3 tt-results/scripts/parse_zkvm_tpch.py
"""

import csv
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR.parent / "raw"
TIDY_DIR = SCRIPT_DIR.parent / "tidy"
PASSES = [("cuda", "gpu")]

TPCH_HEADER = [
    "Q", "variant", "scale-factor", "prover", "mode",
    "prover time (s)", "verifier time (ms)", "proof size (KB)", "raw proof (B)",
    "cycles", "result rows",
]
COMMIT_HEADER = ["table", "scale-factor", "latency(ms)", "size(KB)"]


def fmt(value, decimals):
    s = f"{value:.{decimals}f}"
    return s.rstrip("0").rstrip(".") if "." in s else s


def main():
    rows, tables = [], {}
    for tag, prover in PASSES:
        path = RAW_DIR / f"zkvm_tpch_{tag}.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        for r in data["results"]:
            rows.append([
                f"q{r['query']}", r["variant"], r["sf"], prover, r["mode"],
                fmt(r["prove_ms"] / 1000, 3), fmt(r["verify_ms"], 3),
                fmt(r["proof_bytes"] / 1024, 3), str(r["raw_proof_bytes"]),
                str(r["cycles"]), str(r["result_rows"]),
            ])
        for t in data["tables"]:
            tables.setdefault((t["name"], t["sf"]), [
                t["name"], t["sf"], fmt(t["commit_ms"], 4), fmt(t["commitment_bytes"] / 1024, 3),
            ])
    if not rows:
        print(f"No zkVM TPC-H JSON found in {RAW_DIR}; nothing to do.")
        return
    rows.sort(key=lambda r: (r[1], float(r[2]), int(r[0][1:]), r[3], r[4]))
    TIDY_DIR.mkdir(parents=True, exist_ok=True)
    with open(TIDY_DIR / "tpch_zkvm.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(TPCH_HEADER)
        w.writerows(rows)
    with open(TIDY_DIR / "commit_zkvm.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(COMMIT_HEADER)
        w.writerows(sorted(tables.values(), key=lambda r: (float(r[1]), r[0])))
    print(f"Wrote tpch_zkvm.csv ({len(rows)} rows), commit_zkvm.csv ({len(tables)} rows)")


if __name__ == "__main__":
    main()
