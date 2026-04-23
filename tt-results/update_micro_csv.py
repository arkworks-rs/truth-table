#!/usr/bin/env python3
"""
Rebuild micro-benchmark rows in tidy/micro.csv from the third-party bench JSONs.

Reads (any subset that exists):
  raw/third_party_sxt_proof_of_sql.json  → System=PoSQL
  raw/third_party_qedb.json              → System=QEDB
  raw/third_party_truth_table.json       → System=TT

For each JSON that exists, every row in tidy/micro.csv for that System is
removed and replaced with fresh rows from the JSON. Systems whose JSON is
missing are left untouched.

Query-name mapping (JSON → CSV Q column):
  filter / Filter              → Filter
  aggregate_count / Aggregate  → Aggregate
  join / Join                  → Join
  join_pk_fk / Join PK/FK      → Join PK/FK
  limit_offset / Limit Offset  → Limit

Units:
  prover time (s)     = prove_ms / 1000
  verifier time (ms)  = verify_ms
  proof size (KB)     = proof_bytes / 1024

Usage:
  python3 tt-results/update_micro_csv.py
"""

import csv
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR / "raw"
CSV_PATH = SCRIPT_DIR / "tidy" / "micro.csv"

DEFAULT_HEADER = [
    "Q",
    "threads",
    "System",
    "table log size",
    "prover time (s)",
    "verifier time (ms)",
    "proof size (KB)",
]

# JSON bench name → (CSV System label, raw-file name)
BENCH_SOURCES = [
    ("sxt_proof_of_sql", "PoSQL", "third_party_sxt_proof_of_sql.json"),
    ("qedb", "QEDB", "third_party_qedb.json"),
    ("truth_table", "TT", "third_party_truth_table.json"),
]

# Normalise the query names each bench emits into the CSV's Q column.
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

# Stable CSV ordering inside each (System, threads, pow) group.
Q_ORDER = ["Filter", "Aggregate", "Join", "Join PK/FK", "Limit"]
SYSTEM_ORDER = {"TT": 0, "QEDB": 1, "PoSQL": 2}


def fmt(value, decimals=3):
    """Render a float the way the existing CSV does (trim trailing zeros)."""
    if value is None:
        return ""
    s = f"{value:.{decimals}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s


def rows_from_json(json_path: Path, system_label: str) -> list[list[str]]:
    data = json.loads(json_path.read_text())
    threads = str(data.get("config", {}).get("num_threads", ""))
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
        rows.append([
            q,
            threads,
            system_label,
            str(pow_val) if pow_val is not None else "",
            fmt(prove_ms / 1000) if prove_ms is not None else "",
            fmt(verify_ms, decimals=0) if verify_ms is not None else "",
            fmt(proof_bytes / 1024) if proof_bytes is not None else "",
        ])
    return rows


def sort_key(row):
    q = row[0]
    try:
        threads = int(row[1])
    except ValueError:
        threads = 10**9
    system = row[2]
    try:
        pow_val = int(row[3])
    except ValueError:
        pow_val = 10**9
    q_idx = Q_ORDER.index(q) if q in Q_ORDER else len(Q_ORDER)
    sys_idx = SYSTEM_ORDER.get(system, len(SYSTEM_ORDER))
    return (threads, pow_val, sys_idx, q_idx)


def main():
    # ── Read current CSV and keep rows for systems we're NOT refreshing.
    header = None
    carried_rows: list[list[str]] = []
    refreshed_systems: set[str] = set()

    # Decide upfront which systems we're refreshing (where the JSON exists).
    refresh_plan = []
    for bench_name, system_label, filename in BENCH_SOURCES:
        path = RAW_DIR / filename
        if path.exists():
            refresh_plan.append((bench_name, system_label, path))
            refreshed_systems.add(system_label)

    if not refresh_plan:
        print(f"No third-party JSON found in {RAW_DIR}; nothing to do.")
        return

    if CSV_PATH.exists():
        with open(CSV_PATH) as f:
            reader = csv.reader(f)
            header = next(reader)
            if header and header[0].startswith("\ufeff"):
                header[0] = header[0].lstrip("\ufeff")
            for row in reader:
                if len(row) >= 3 and row[2] in refreshed_systems:
                    continue  # drop — will be replaced
                if not row:
                    continue
                carried_rows.append(row)

    if header is None:
        header = list(DEFAULT_HEADER)

    # ── Collect fresh rows from each JSON.
    fresh_rows: list[list[str]] = []
    for bench_name, system_label, path in refresh_plan:
        rows = rows_from_json(path, system_label)
        print(f"{system_label}: {len(rows)} rows from {path.name}")
        fresh_rows.extend(rows)

    all_rows = carried_rows + fresh_rows
    all_rows.sort(key=sort_key)

    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(all_rows)

    print(
        f"Wrote {CSV_PATH}: {len(all_rows)} rows "
        f"(refreshed: {', '.join(sorted(refreshed_systems))})"
    )


if __name__ == "__main__":
    main()
