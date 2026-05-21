#!/usr/bin/env python3
"""
Rebuild tidy/tpch.csv from TruthTable TPC-H raw outputs (the `_tt` bench
variants only). The `_pgn` variants live in tidy/tpch_pgn.csv — see
parse_pgn.py.

Reads:
  raw/benches_tt_{SF}_{threads}.json     — divan prover/verifier timing
  raw/bench_stats_tt_{SF}_{threads}.jsonl — proof sizes (tracing stats layer)

Writes:
  tidy/tpch.csv (System=tt rows, one per (Q, SF) cell)

Proof sizes:
  proof size core  = crypto compressed size (zstd)
  plan size        = non_crypto size (opt-hints, uncompressed)
  total proof size = full compressed size (zstd)

Usage:
  python3 tt-results/scripts/parse_tt_tpch.py
"""

import csv
import json
import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR.parent / "raw"
CSV_PATH = SCRIPT_DIR.parent / "tidy" / "tpch.csv"

# (SF, threads) combinations that run_tt_tpch.sh produces. SF=0.01/0.02/0.04
# live in tpch_pgn.csv (Poneglyph comparison), not tpch.csv — they're produced
# by run_pgn.sh, not run_tt_tpch.sh.
RUNS = [
    ("0.05", "4"),
    ("0.05", "1"),
    ("0.1", "4"),
    ("0.1", "1"),
]

HEADER = [
    "Q", "System", "scale-factor",
    "prover time 4threads (s)", "prover time 1thread (s)",
    "total verifier time (ms)", "core verifier time (ms)",
    "preprocessed veritifier time (ms)",
    "proof size core(KB)", "plan size (KB)", "total proof size (KB)",
]


def parse_time_to_seconds(s):
    if s is None:
        return None
    m = re.match(r"([\d.]+)\s*([a-zµ]+)", s.strip())
    if not m:
        return None
    v, u = float(m.group(1)), m.group(2)
    return {"m": v * 60, "s": v, "ms": v / 1000, "µs": v / 1e6, "us": v / 1e6}.get(u)


def parse_time_to_ms(s):
    sec = parse_time_to_seconds(s)
    return sec * 1000 if sec is not None else None


def case_to_q(case_name):
    """tpch_q8_tt → q8. Returns None for non-_tt cases."""
    m = re.match(r"tpch_q(\d+)_tt$", case_name)
    return f"q{m.group(1)}" if m else None


def load_timing(path):
    if not path.exists():
        return {}
    d = json.loads(path.read_text())
    cases = d.get("benches", {}).get("tpch", {})
    out = {}
    for name, data in cases.items():
        prover = data.get("prover", {}).get("time", {}).get("median")
        vc = data.get("verifier_crypto", {}).get("time", {}).get("median")
        vf = data.get("verifier_full", {}).get("time", {}).get("median")
        out[name] = {
            "prover_s": parse_time_to_seconds(prover),
            "vc_ms": parse_time_to_ms(vc),
            "vf_ms": parse_time_to_ms(vf),
        }
    return out


def load_sizes(path, case_order):
    """Positional match: each `proof_size` jsonl entry → next case in order."""
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
        out[case_name] = {
            "core_kb": int(ps.get("crypto", {}).get("compressed size", 0)) / 1024,
            "plan_kb": int(ps.get("non_crypto", {}).get("size", 0)) / 1024,
            "total_kb": int(ps.get("full", {}).get("compressed size", 0)) / 1024,
        }
    return out


def fmt(v, decimals=2):
    return f"{v:.{decimals}f}" if v is not None else ""


def main():
    # data[(Q, SF)] = aggregated record across thread counts.
    data = {}

    for sf, threads in RUNS:
        tag = f"{sf}_{threads}"
        timing = load_timing(RAW_DIR / f"benches_tt_{tag}.json")
        case_order = list(timing.keys())
        sizes = load_sizes(RAW_DIR / f"bench_stats_tt_{tag}.jsonl", case_order)

        for case in case_order:
            q = case_to_q(case)
            if q is None:
                continue
            rec = data.setdefault((q, sf), {})
            t = timing[case]
            s = sizes.get(case, {})

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

            # Proof sizes are thread-independent; take whichever has them.
            if s.get("core_kb"):
                rec["core_kb"] = s["core_kb"]
            if s.get("plan_kb") is not None:
                rec["plan_kb"] = s["plan_kb"]
            if s.get("total_kb"):
                rec["total_kb"] = s["total_kb"]

    def sort_key(key):
        q, sf = key
        m = re.match(r"q(\d+)$", q)
        n = int(m.group(1)) if m else 999
        return (n, float(sf))

    rows = []
    for (q, sf) in sorted(data.keys(), key=sort_key):
        rec = data[(q, sf)]
        vf = rec.get("vf_ms")
        vc = rec.get("vc_ms")
        preproc = (vf - vc) if (vf is not None and vc is not None) else None
        rows.append([
            q, "tt", sf,
            fmt(rec.get("prover_4t")), fmt(rec.get("prover_1t")),
            fmt(vf), fmt(vc), fmt(preproc),
            fmt(rec.get("core_kb")), fmt(rec.get("plan_kb")), fmt(rec.get("total_kb")),
        ])

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(rows)

    json_count = sum(1 for sf, t in RUNS if (RAW_DIR / f"benches_tt_{sf}_{t}.json").exists())
    jsonl_count = sum(1 for sf, t in RUNS if (RAW_DIR / f"bench_stats_tt_{sf}_{t}.jsonl").exists())
    print(f"Wrote {CSV_PATH}: {len(rows)} tt rows")
    print(f"Data sources: {json_count} JSON + {jsonl_count} JSONL files")


if __name__ == "__main__":
    main()
