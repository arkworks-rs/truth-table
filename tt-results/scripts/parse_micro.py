#!/usr/bin/env python3
"""
Rebuild tidy/micro.csv from the per-system JSONs run_micro.sh writes to raw/.

Sources (any that exist):
  third_party_truth_table.json      → TT
  third_party_sxt_proof_of_sql.json → PoSQL (arkworks MSMs)
  third_party_qedb.json             → QEDB
  third_party_poneglyph.json        → Poneglyph, and "Poneglyph
                                      (data-independent)" for its
                                      fixed-selector circuits
  third_party_baseline_{1,4}.json   → Baseline (curve "none")
  zkvm_micro_cuda.json              → "zkVM (GPU)" and, for its Groth16
                                      wrap, "zkVM (GPU, Groth16)"

Every proof system runs on BN254. A metric a system does not have is empty:
  prover time (s), verifier time (ms) (median within a second), proof size (KB)
  setup time (s)            universal setup: TT's keys, PoSQL's and QEDB's
                            reference strings, Poneglyph's KZG parameters,
                            the zkVM's program keys
  pk size (KB), vk size (KB)
  params size (KB)          Poneglyph's KZG parameters, beside its circuit keys
  keygen time (s)           Poneglyph's per-circuit key generation
  preprocess time (s)       TT's padding of the table before committing it
  commit time (s), commitment size (KB)   the data owner's commitment or hashes
  execution time (s)        Baseline: the query on the full tables, unverified
  result rows, public inputs, zkvm cycles

Usage:
  python3 tt-results/scripts/parse_micro.py
"""

import csv
import json
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR.parent / "raw"
CSV_PATH = SCRIPT_DIR.parent / "tidy" / "micro.csv"

# (JSON file, System, curve)
SOURCES = [
    ("third_party_truth_table.json", "TT", "bn254"),
    ("third_party_sxt_proof_of_sql.json", "PoSQL", "bn254"),
    ("third_party_qedb.json", "QEDB", "bn254"),
    ("third_party_poneglyph.json", "Poneglyph", "bn254"),
    ("third_party_baseline_1.json", "Baseline", "none"),
    ("third_party_baseline_4.json", "Baseline", "none"),
    ("zkvm_micro_cuda.json", "zkVM (GPU)", "bn254"),
]

QUERY_NAME_MAP = {
    "filter_0p1": "Filter 0.1%",
    "filter_1": "Filter 1%",
    "filter_10": "Filter 10%",
    "aggregate": "Aggregate",
    "range": "Range",
    "in_list": "IN list",
    "arithmetic": "Arithmetic",
    "group_by": "Group by",
    "join_pk_fk": "Join PK/FK",
    "join_m2m": "Join M:N",
    "order_by": "Order by",
}
Q_ORDER = list(QUERY_NAME_MAP.values())
SYSTEM_ORDER = [
    "TT",
    "PoSQL",
    "QEDB",
    "Poneglyph",
    "Poneglyph (data-independent)",
    "zkVM (GPU)",
    "zkVM (GPU, Groth16)",
    "Baseline",
]

# (CSV column, JSON field, scale)
METRICS = [
    ("prover time (s)", "prove_ms", 1e-3),
    ("verifier time (ms)", "verify_ms", 1),
    ("proof size (KB)", "proof_bytes", 1 / 1024),
    ("setup time (s)", "setup_ms", 1e-3),
    ("pk size (KB)", "pk_bytes", 1 / 1024),
    ("vk size (KB)", "vk_bytes", 1 / 1024),
    ("params size (KB)", "params_bytes", 1 / 1024),
    ("keygen time (s)", "keygen_ms", 1e-3),
    ("preprocess time (s)", "preprocess_ms", 1e-3),
    ("commit time (s)", "commit_ms", 1e-3),
    ("commitment size (KB)", "commitment_bytes", 1 / 1024),
    ("execution time (s)", "execute_ms", 1e-3),
    ("result rows", "result_rows", 1),
    ("public inputs", "public_inputs", 1),
    ("zkvm cycles", "cycles", 1),
]
HEADER = ["Q", "threads", "System", "curve", "table log size"] + [c for c, _, _ in METRICS]


def fmt(value):
    if value is None:
        return ""
    s = f"{value:.7f}"
    return s.rstrip("0").rstrip(".") if "." in s else s


def rows_from_json(path, system, curve):
    data = json.loads(path.read_text())
    threads = data.get("config", {}).get("num_threads", "")
    if system.startswith("zkVM"):
        threads = "gpu"
    rows = []
    for entry in data.get("results", []):
        q = QUERY_NAME_MAP.get(str(entry.get("query")))
        if q is None:
            continue
        label = entry.get("system", system)
        if entry.get("mode") == "groth16":
            label = "zkVM (GPU, Groth16)"
        row = [q, threads, label, curve, entry.get("pow", "")]
        for _, field, scale in METRICS:
            value = entry.get(field)
            row.append(fmt(value * scale) if isinstance(value, (int, float)) else "")
        rows.append(row)
    return rows


def main():
    rows = []
    for filename, system, curve in SOURCES:
        path = RAW_DIR / filename
        if path.exists():
            found = rows_from_json(path, system, curve)
            print(f"{system}: {len(found)} rows from {filename}")
            rows.extend(found)
    if not rows:
        print(f"No micro JSON found in {RAW_DIR}; nothing to do.")
        return

    def key(row):
        system = SYSTEM_ORDER.index(row[2]) if row[2] in SYSTEM_ORDER else len(SYSTEM_ORDER)
        return (str(row[1]), int(row[4] or 0), system, Q_ORDER.index(row[0]))

    rows.sort(key=key)
    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(rows)
    print(f"Wrote {CSV_PATH}: {len(rows)} rows")


if __name__ == "__main__":
    main()
