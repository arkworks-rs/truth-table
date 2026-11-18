#!/usr/bin/env python3
"""
Rebuild tidy/micro.csv from the per-bench JSONs produced by run_micro.sh.

Reads (any subset that exists):
  raw/third_party_sxt_proof_of_sql.json  → System=PoSQL
  raw/third_party_qedb.json              → System=QEDB
  raw/third_party_truth_table.json       → System=TT
  raw/third_party_baseline_<threads>.json → System=Baseline (curve "none")
  raw/third_party_zkvm_cpu<threads>.json → System=zkVM (SP1, curve "none")
  raw/third_party_zkvm_cuda.json         → System=zkVM (GPU), threads "gpu"
  A zkVM run proved with a Groth16 wrap gets ", Groth16" in its System:
  "zkVM (Groth16)", "zkVM (GPU, Groth16)".

Writes:
  tidy/micro.csv

For each JSON that exists, every row in micro.csv with that JSON's
(System, curve, threads) is replaced. Rows of other combinations are left
untouched.

Query-name mapping (JSON → CSV Q):
  filter / Filter              → Filter
  aggregate_count / Aggregate  → Aggregate
  join / Join                  → Join
  join_pk_fk / Join PK/FK      → Join PK/FK
  limit_offset / Limit Offset  → Limit

Units:
  prover time (s)     = prove_ms / 1000
  verifier time (ms)  = verify_ms
  proof size (KB)     = proof_bytes / 1024
  commit time (s)       = commit_ms / 1000       (Baseline and zkVM)
  commitment size (KB)  = commitment_bytes / 1024 (Baseline and zkVM)
  execution time (s)    = execute_ms / 1000      (Baseline only: the query
                          on the full tables, unverified)
  zkvm cycles           = instructions the zkVM guest ran (zkVM only)

Usage:
  python3 tt-results/scripts/parse_micro.py
"""

import csv
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR.parent / "raw"
CSV_PATH = SCRIPT_DIR.parent / "tidy" / "micro.csv"

DEFAULT_HEADER = [
    "Q",
    "threads",
    "System",
    "curve",
    "table log size",
    "prover time (s)",
    "verifier time (ms)",
    "proof size (KB)",
    "commit time (s)",
    "commitment size (KB)",
    "execution time (s)",
    "zkvm cycles",
]

# (bench_name, System label, default_curve, JSON filename)
# default_curve is used when the JSON doesn't carry an explicit config.curve
# (PoSQL is hard-coded to BN254 via HyperKZG; QEDB is hard-coded to BLS12-381).
# TT runs once per curve, writing to a curve-suffixed JSON. Baseline uses no
# curve and runs once per thread count.
BENCH_SOURCES = [
    ("sxt_proof_of_sql", "PoSQL", "bn254", "third_party_sxt_proof_of_sql.json"),
    ("qedb", "QEDB", "bls12_381", "third_party_qedb.json"),
    ("truth_table", "TT", "bn254", "third_party_truth_table.json"),
    ("truth_table", "TT", "bls12_381", "third_party_truth_table_bls12_381.json"),
    ("baseline", "Baseline", "none", "third_party_baseline_1.json"),
    ("baseline", "Baseline", "none", "third_party_baseline_4.json"),
    ("zkvm", "zkVM", "none", "third_party_zkvm_cpu1.json"),
    ("zkvm", "zkVM", "none", "third_party_zkvm_cpu4.json"),
    ("zkvm", "zkVM (GPU)", "none", "third_party_zkvm_cuda.json"),
]

QUERY_NAME_MAP = {
    "filter": "Filter",
    "Filter": "Filter",
    "aggregate_count": "Aggregate",
    "Aggregate": "Aggregate",
    "join": "Join",
    "Join": "Join",
    "join_pk_fk": "Join PK/FK",
    "Join PK/FK": "Join PK/FK",
    "limit_offset": "Limit",
    "Limit Offset": "Limit",
}

Q_ORDER = ["Filter", "Aggregate", "Join", "Join PK/FK", "Limit"]
SYSTEM_ORDER = {
    "TT": 0,
    "QEDB": 1,
    "PoSQL": 2,
    "zkVM": 3,
    "zkVM (Groth16)": 4,
    "zkVM (GPU)": 5,
    "zkVM (GPU, Groth16)": 6,
    "Baseline": 7,
}


def zkvm_system(label, mode):
    if mode != "groth16":
        return label
    return label[:-1] + ", Groth16)" if label.endswith(")") else label + " (Groth16)"


def fmt(value, decimals=3):
    if value is None:
        return ""
    s = f"{value:.{decimals}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s


def rows_from_json(json_path, system_label, default_curve):
    data = json.loads(json_path.read_text())
    threads = str(data.get("config", {}).get("num_threads", ""))
    if data.get("config", {}).get("prover") == "cuda":
        threads = "gpu"
    # Prefer config.curve when present (TT writes one), otherwise fall back to
    # the hard-coded default (PoSQL=BN254, QEDB=BLS12-381).
    curve = data.get("config", {}).get("curve", default_curve)
    rows = []
    for entry in data.get("results", []):
        q_raw = entry.get("query")
        q = QUERY_NAME_MAP.get(q_raw)
        if q is None:
            print(f"  skipping unmapped query {q_raw!r} in {json_path.name}", file=sys.stderr)
            continue
        pow_val = entry.get("pow")
        prove_ms = entry.get("prove_ms")
        verify_ms = entry.get("verify_ms")
        proof_bytes = entry.get("proof_bytes")
        # TT's commit_ms is an oracle-cache lookup, not a commit.
        commit_ms = entry.get("commit_ms") if system_label != "TT" else None
        commitment_bytes = entry.get("commitment_bytes")
        execute_ms = entry.get("execute_ms")
        # Per-row curve takes precedence (TT emits it on each result line).
        row_curve = entry.get("curve", curve)
        rows.append([
            q,
            threads,
            zkvm_system(system_label, entry.get("mode")),
            row_curve,
            str(pow_val) if pow_val is not None else "",
            # Baseline times are fractional milliseconds; trailing zeros are
            # stripped, so whole-millisecond times print as before.
            fmt(prove_ms / 1000, decimals=7) if prove_ms is not None else "",
            fmt(verify_ms, decimals=4) if verify_ms is not None else "",
            fmt(proof_bytes / 1024) if proof_bytes is not None else "",
            fmt(commit_ms / 1000, decimals=7) if commit_ms is not None else "",
            fmt(commitment_bytes / 1024) if commitment_bytes is not None else "",
            fmt(execute_ms / 1000, decimals=7) if execute_ms is not None else "",
            str(entry["cycles"]) if "cycles" in entry else "",
        ])
    return rows


CURVE_ORDER = {"bn254": 0, "bls12_381": 1}


def sort_key(row):
    q = row[0]
    try:
        threads = int(row[1])
    except ValueError:
        threads = 10**9
    system = row[2]
    curve = row[3]
    try:
        pow_val = int(row[4])
    except ValueError:
        pow_val = 10**9
    q_idx = Q_ORDER.index(q) if q in Q_ORDER else len(Q_ORDER)
    sys_idx = SYSTEM_ORDER.get(system, len(SYSTEM_ORDER))
    curve_idx = CURVE_ORDER.get(curve, len(CURVE_ORDER))
    return (threads, pow_val, sys_idx, curve_idx, q_idx)


def main():
    header = None
    carried_rows = []
    refresh_plan = []
    for bench_name, system_label, default_curve, filename in BENCH_SOURCES:
        path = RAW_DIR / filename
        if path.exists():
            refresh_plan.append((bench_name, system_label, default_curve, path))

    if not refresh_plan:
        print(f"No third-party JSON found in {RAW_DIR}; nothing to do.")
        return

    fresh_rows = []
    for bench_name, system_label, default_curve, path in refresh_plan:
        rows = rows_from_json(path, system_label, default_curve)
        print(f"{system_label}@{default_curve}: {len(rows)} rows from {path.name}")
        fresh_rows.extend(rows)
    # Refresh by (System, curve, threads): a new TT@bn254 JSON must not clobber
    # the TT@bls12_381 rows, nor a 4-thread Baseline JSON the 1-thread rows.
    refreshed = {(row[2], row[3], row[1]) for row in fresh_rows}

    # Per-system default curve for upgrading legacy rows that predate the
    # `curve` column. Derived from BENCH_SOURCES so it stays in sync with the
    # canonical "what curve does each system natively use" mapping.
    # PoSQL → bn254, QEDB → bls12_381, TT → bn254 (its original/default
    # backend; the BLS12-381 variant didn't exist when these rows were
    # written, so they can't possibly be from a TT@bls12_381 run).
    legacy_curve_for = {
        system_label: default_curve
        for _, system_label, default_curve, _ in BENCH_SOURCES
    }

    if CSV_PATH.exists():
        with open(CSV_PATH) as f:
            reader = csv.reader(f)
            header = next(reader)
            if header and header[0].startswith("\ufeff"):
                header[0] = header[0].lstrip("\ufeff")
            has_curve_col = "curve" in [c.strip() for c in header]
            if not has_curve_col:
                header.insert(3, "curve")
            for row in reader:
                if not row:
                    continue
                if not has_curve_col and len(row) >= 3:
                    system = row[2]
                    legacy_curve = legacy_curve_for.get(system, "bn254")
                    row = row[:3] + [legacy_curve] + row[3:]
                if len(row) >= 4 and (row[2], row[3], row[1]) in refreshed:
                    continue
                carried_rows.append(row)
        # Columns added after the CSV was written stay empty in its old rows.
        header += [c for c in DEFAULT_HEADER if c not in header]
        carried_rows = [row + [""] * (len(header) - len(row)) for row in carried_rows]

    if header is None:
        header = list(DEFAULT_HEADER)

    all_rows = carried_rows + fresh_rows
    all_rows.sort(key=sort_key)

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(all_rows)

    refreshed_labels = sorted(f"{s}@{c}/{t}t" for s, c, t in refreshed)
    print(
        f"Wrote {CSV_PATH}: {len(all_rows)} rows "
        f"(refreshed: {', '.join(refreshed_labels)})"
    )


if __name__ == "__main__":
    main()
