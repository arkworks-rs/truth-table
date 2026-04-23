#!/usr/bin/env python3
"""
Rebuild tt rows in tidy/tpch.csv from the raw benchmark JSON/JSONL files.

Reads:
  raw/benches_{SF}_{threads}.json   — prover/verifier timing (divan output)
  raw/bench_stats_{SF}_{threads}.jsonl — proof sizes (tracing stats layer)

Writes:
  tidy/tpch.csv — removes all System=tt rows, then inserts fresh ones.

Mapping from bench case name to CSV Q column:
  tpch_q{N}_tt  → q{N}
  tpch_q{N}_pgn → q{N}_p

Proof sizes:
  proof size core  = crypto compressed size (zstd)
  plan size        = non_crypto size (opt-hints, uncompressed — tiny)
  total proof size = full compressed size (zstd)

Usage:
  python3 tt-results/update_tpch_csv.py
"""

import csv
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR / "raw"
CSV_PATH = SCRIPT_DIR / "tidy" / "tpch.csv"

# ── Known (SF, threads) runs ────────────────────────────────────────
# Must match what run_all.sh produces.
RUNS = [
    ("0.01", "1"),
    ("0.02", "1"),
    ("0.04", "1"),
    ("0.05", "4"),
    ("0.05", "1"),
    ("0.1", "4"),
    ("0.1", "1"),
]


# ── Helpers ─────────────────────────────────────────────────────────
def parse_time_to_seconds(s: str) -> float | None:
    """Convert divan time string to seconds: '1.093 m' → 65.58."""
    if s is None:
        return None
    m = re.match(r"([\d.]+)\s*([a-zµ]+)", s.strip())
    if not m:
        return None
    v, u = float(m.group(1)), m.group(2)
    return {"m": v * 60, "s": v, "ms": v / 1000, "µs": v / 1e6, "us": v / 1e6}.get(u)


def parse_time_to_ms(s: str) -> float | None:
    """Convert divan time string to milliseconds."""
    sec = parse_time_to_seconds(s)
    return sec * 1000 if sec is not None else None


def case_to_csv_q(case_name: str) -> str | None:
    """tpch_q8_tt → q8, tpch_q3_pgn → q3_p."""
    m = re.match(r"tpch_q(\d+)_(tt|pgn)$", case_name)
    if not m:
        return None
    n, variant = m.group(1), m.group(2)
    return f"q{n}_p" if variant == "pgn" else f"q{n}"


def load_json_timing(path: Path) -> dict[str, dict]:
    """Load benches_{SF}_{T}.json → {case_name: {prover_s, vc_ms, vf_ms}}."""
    if not path.exists():
        return {}
    d = json.loads(path.read_text())
    cases = d.get("benches", {}).get("tpch", {})
    out = {}
    for name, data in cases.items():
        prover_median = data.get("prover", {}).get("time", {}).get("median")
        vc_median = data.get("verifier_crypto", {}).get("time", {}).get("median")
        vf_median = data.get("verifier_full", {}).get("time", {}).get("median")
        out[name] = {
            "prover_s": parse_time_to_seconds(prover_median),
            "vc_ms": parse_time_to_ms(vc_median),
            "vf_ms": parse_time_to_ms(vf_median),
        }
    return out


def load_jsonl_proof_sizes(path: Path, case_order: list[str]) -> dict[str, dict]:
    """Load bench_stats_{SF}_{T}.jsonl → {case_name: {core_kb, plan_kb, total_kb}}.

    Matches proof_size entries to case names by position (verified to be
    in the same order as the divan JSON keys).
    """
    if not path.exists():
        return {}
    entries = []
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            if "proof_size" in d:
                entries.append(d["proof_size"])
    out = {}
    for case_name, ps in zip(case_order, entries):
        crypto_compressed = int(ps.get("crypto", {}).get("compressed size", 0))
        non_crypto = int(ps.get("non_crypto", {}).get("size", 0))
        full_compressed = int(ps.get("full", {}).get("compressed size", 0))
        out[case_name] = {
            "core_kb": crypto_compressed / 1024,
            "plan_kb": non_crypto / 1024,
            "total_kb": full_compressed / 1024,
        }
    return out


# ── Main ────────────────────────────────────────────────────────────
def main():
    # Collect all data: data[csv_q][sf] = {prover_1t, prover_4t, vc_ms, vf_ms, core_kb, ...}
    data: dict[str, dict[str, dict]] = {}

    for sf, threads in RUNS:
        tag = f"{sf}_{threads}"
        json_path = RAW_DIR / f"benches_{tag}.json"
        jsonl_path = RAW_DIR / f"bench_stats_{tag}.jsonl"

        timing = load_json_timing(json_path)
        case_order = list(timing.keys())
        sizes = load_jsonl_proof_sizes(jsonl_path, case_order)

        for case_name in case_order:
            csv_q = case_to_csv_q(case_name)
            if csv_q is None:
                continue
            key = (csv_q, sf)
            if key not in data:
                data[key] = {}
            rec = data[key]

            t = timing.get(case_name, {})
            s = sizes.get(case_name, {})

            if threads == "1":
                if t.get("prover_s") is not None:
                    rec["prover_1t"] = t["prover_s"]
                if t.get("vf_ms") is not None:
                    rec["vf_ms"] = t["vf_ms"]
                if t.get("vc_ms") is not None:
                    rec["vc_ms"] = t["vc_ms"]
            elif threads == "4":
                if t.get("prover_s") is not None:
                    rec["prover_4t"] = t["prover_s"]

            # Proof sizes are thread-independent; take from whichever run has them.
            if s.get("core_kb"):
                rec["core_kb"] = s["core_kb"]
            if s.get("plan_kb") is not None:
                rec["plan_kb"] = s["plan_kb"]
            if s.get("total_kb"):
                rec["total_kb"] = s["total_kb"]

    # Read existing CSV, keep non-tt rows.
    header = None
    non_tt_rows = []
    if CSV_PATH.exists():
        with open(CSV_PATH) as f:
            reader = csv.reader(f)
            header = next(reader)
            # Strip BOM if present.
            if header[0].startswith("\ufeff"):
                header[0] = header[0].lstrip("\ufeff")
            for row in reader:
                if len(row) >= 2 and row[1].strip() != "tt":
                    non_tt_rows.append(row)

    if header is None:
        header = [
            "Q", "System", "scale-factor",
            "prover time 4threads (s)", "prover time 1thread (s)",
            "total verifier time (ms)", "core verifier time (ms)",
            "preprocessed veritifier time (ms)",
            "proof size core(KB)", "plan size (KB)", "total proof size (KB)",
        ]

    # Build new tt rows sorted by (query_number, variant, sf).
    def sort_key(qsf):
        csv_q, sf = qsf
        m = re.match(r"q(\d+)(_p)?$", csv_q)
        n = int(m.group(1)) if m else 999
        is_p = 1 if m and m.group(2) else 0
        return (n, is_p, float(sf))

    tt_rows = []
    for (csv_q, sf) in sorted(data.keys(), key=sort_key):
        rec = data[(csv_q, sf)]
        prover_4t = rec.get("prover_4t")
        prover_1t = rec.get("prover_1t")
        vf = rec.get("vf_ms")
        vc = rec.get("vc_ms")
        preproc = (vf - vc) if (vf is not None and vc is not None) else None
        core_kb = rec.get("core_kb")
        plan_kb = rec.get("plan_kb")
        total_kb = rec.get("total_kb")

        def fmt(v, decimals=2):
            return f"{v:.{decimals}f}" if v is not None else ""

        tt_rows.append([
            csv_q, "tt", sf,
            fmt(prover_4t), fmt(prover_1t),
            fmt(vf), fmt(vc), fmt(preproc),
            fmt(core_kb), fmt(plan_kb), fmt(total_kb),
        ])

    # Interleave: for each (Q, SF) group, put tt rows first, then non-tt.
    # Build a combined list sorted by (query_number, variant, sf, system).
    all_rows = []
    for row in tt_rows:
        all_rows.append(row)
    for row in non_tt_rows:
        all_rows.append(row)

    # Sort everything together.
    def global_sort_key(row):
        q = row[0] if len(row) > 0 else ""
        system = row[1] if len(row) > 1 else ""
        sf = row[2] if len(row) > 2 else "0"
        m = re.match(r"q(\d+)(_p)?$", q)
        n = int(m.group(1)) if m else 999
        is_p = 1 if m and m.group(2) else 0
        sys_order = 0 if system == "tt" else 1
        try:
            sf_val = float(sf)
        except ValueError:
            sf_val = 999
        return (n, is_p, sf_val, sys_order)

    all_rows.sort(key=global_sort_key)

    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(all_rows)

    tt_count = sum(1 for r in all_rows if len(r) >= 2 and r[1] == "tt")
    other_count = len(all_rows) - tt_count
    print(f"Wrote {CSV_PATH}: {tt_count} tt rows, {other_count} other rows")
    print(f"Data sources: {len([1 for p in [RAW_DIR/f'benches_{sf}_{t}.json' for sf,t in RUNS] if p.exists()])} JSON + "
          f"{len([1 for p in [RAW_DIR/f'bench_stats_{sf}_{t}.jsonl' for sf,t in RUNS] if p.exists()])} JSONL files")


if __name__ == "__main__":
    main()
