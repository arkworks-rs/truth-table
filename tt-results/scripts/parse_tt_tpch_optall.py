#!/usr/bin/env python3
"""
Rebuild tidy/tpch_optall.csv from the bundled-optimization sweep outputs.

Reads:
  raw/benches_tt_optall_0.05_1.json         — divan timing
  raw/bench_stats_tt_optall_0.05_1.jsonl    — proof sizes (tracing stats)

Writes:
  tidy/tpch_optall.csv with columns:
    Q, config, scale-factor, threads,
    prover time (s), total verifier time (ms), total proof size (KB)

Each row is one (query, config) cell. `config` is one of: all_off,
pkfk_on_remat_off, pkfk_off_remat_on. (The `all_on` config — both rules
enabled, i.e., production defaults — is covered by the baseline
`tpch` bench and intentionally omitted here.)

Usage:
  python3 tt-results/scripts/parse_tt_tpch_optall.py
"""

import csv
import json
import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR.parent / "raw"
CSV_PATH = SCRIPT_DIR.parent / "tidy" / "tpch_optall.csv"

SCALE_FACTOR = "0.05"
THREADS = "1"

CONFIGS = ["all_off", "pkfk_on_remat_off", "pkfk_off_remat_on"]
CONFIG_ALT = "|".join(CONFIGS)

HEADER = [
    "Q", "config", "scale-factor", "threads",
    "prover time (s)", "total verifier time (ms)", "total proof size (KB)",
]

CASE_RE = re.compile(rf"^tpch_q(\d+)_tt_({CONFIG_ALT})$")
MODULE_RE = re.compile(rf"^q(\d+)_({CONFIG_ALT})$")


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


def case_to_q_config(case_name):
    """tpch_q5_tt_all_off → ('q5', 'all_off'). None for non-optall names."""
    m = CASE_RE.match(case_name)
    if not m:
        return None
    return f"q{m.group(1)}", m.group(2)


def load_timing(path):
    if not path.exists():
        return {}
    d = json.loads(path.read_text())
    root = d.get("benches", {}).get("tpch_optall", {})
    out = {}
    for module_name, data in root.items():
        # module_name looks like "q5_all_off"; case name is "tpch_q5_tt_all_off"
        m = MODULE_RE.match(module_name)
        if not m:
            continue
        case_name = f"tpch_q{m.group(1)}_tt_{m.group(2)}"
        prover = data.get("prover", {}).get("time", {}).get("median")
        vf = data.get("verifier_full", {}).get("time", {}).get("median")
        out[case_name] = {
            "prover_s": parse_time_to_seconds(prover),
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
            "total_kb": int(ps.get("full", {}).get("compressed size", 0)) / 1024,
        }
    return out


def fmt(v, decimals=2):
    return f"{v:.{decimals}f}" if v is not None else ""


def main():
    timing = load_timing(RAW_DIR / f"benches_tt_optall_{SCALE_FACTOR}_{THREADS}.json")
    case_order = list(timing.keys())
    sizes = load_sizes(
        RAW_DIR / f"bench_stats_tt_optall_{SCALE_FACTOR}_{THREADS}.jsonl",
        case_order,
    )

    rows_by_key = {}
    for case_name in case_order:
        parsed = case_to_q_config(case_name)
        if parsed is None:
            continue
        q, config = parsed
        t = timing.get(case_name, {})
        s = sizes.get(case_name, {})
        rows_by_key[(q, config)] = {
            "prover_s": t.get("prover_s"),
            "vf_ms": t.get("vf_ms"),
            "total_kb": s.get("total_kb"),
        }

    def sort_key(key):
        q, config = key
        m = re.match(r"q(\d+)$", q)
        n = int(m.group(1)) if m else 999
        return (n, CONFIGS.index(config) if config in CONFIGS else 99)

    rows = []
    for (q, config) in sorted(rows_by_key.keys(), key=sort_key):
        rec = rows_by_key[(q, config)]
        rows.append([
            q, config, SCALE_FACTOR, THREADS,
            fmt(rec.get("prover_s")),
            fmt(rec.get("vf_ms")),
            fmt(rec.get("total_kb")),
        ])

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(rows)

    queries = sorted({k[0] for k in rows_by_key})
    configs = sorted({k[1] for k in rows_by_key})
    print(f"Wrote {CSV_PATH}: {len(rows)} rows ({len(queries)} queries × {len(configs)} configs)")


if __name__ == "__main__":
    main()
