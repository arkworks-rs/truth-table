#!/usr/bin/env python3
"""
Rebuild tidy/tpch_pgn.csv — the Poneglyph-comparison CSV containing BOTH:
  - TruthTable on `_pgn` query variants  (System=tt)
  - PoneglyphDB on its KZG queries       (System=poneglyph)

Reads:
  raw/benches_pgn_{SF}_1.json       — divan timing (TT on _pgn variants)
  raw/bench_stats_pgn_{SF}_1.jsonl  — proof sizes (TT on _pgn variants)
  raw/poneglyph_q{N}_k{K}.log       — PoneglyphDB sweep output

Writes:
  tidy/tpch_pgn.csv

Both systems use Q=q{N} in this CSV (no `_p` suffix) — System distinguishes
them. SFs covered: 0.01 / 0.02 / 0.04 (matching PoneglyphDB k=16/17/18).

Usage:
  python3 tt-results/scripts/parse_pgn.py
"""

import csv
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
RAW_DIR = SCRIPT_DIR.parent / "raw"
CSV_PATH = SCRIPT_DIR.parent / "tidy" / "tpch_pgn.csv"

# TT runs at threads=1 only (matches Poneglyph's single-threaded prover).
TT_SFS = ["0.01", "0.02", "0.04"]

# PoneglyphDB k → SF mapping (all six queries share the same mapping;
# Q3's circuit panics at k=15 in practice, so we run k=16/17/18 across
# the board).
PGN_SF_BY_K = {
    "1":  {16: "0.01", 17: "0.02", 18: "0.04"},
    "3":  {16: "0.01", 17: "0.02", 18: "0.04"},
    "5":  {16: "0.01", 17: "0.02", 18: "0.04"},
    "8":  {16: "0.01", 17: "0.02", 18: "0.04"},
    "9":  {16: "0.01", 17: "0.02", 18: "0.04"},
    "18": {16: "0.01", 17: "0.02", 18: "0.04"},
}

HEADER = [
    "Q", "System", "scale-factor",
    "prover time 4threads (s)", "prover time 1thread (s)",
    "total verifier time (ms)", "core verifier time (ms)",
    "preprocessed veritifier time (ms)",
    "proof size core(KB)", "plan size (KB)", "total proof size (KB)",
]


# ── shared helpers ──────────────────────────────────────────────────
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


def fmt(v, decimals=2):
    return f"{v:.{decimals}f}" if v is not None else ""


# ── TT-on-_pgn rows ─────────────────────────────────────────────────
def tt_case_to_q(case_name):
    """tpch_q8_pgn → q8. Returns None for non-_pgn cases."""
    m = re.match(r"tpch_q(\d+)_pgn$", case_name)
    return f"q{m.group(1)}" if m else None


def load_tt_timing(path):
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


def load_tt_sizes(path, case_order):
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


def collect_tt_rows():
    rows = []
    for sf in TT_SFS:
        tag = f"{sf}_1"
        timing = load_tt_timing(RAW_DIR / f"benches_pgn_{tag}.json")
        case_order = list(timing.keys())
        sizes = load_tt_sizes(RAW_DIR / f"bench_stats_pgn_{tag}.jsonl", case_order)

        for case in case_order:
            q = tt_case_to_q(case)
            if q is None:
                continue
            t = timing[case]
            s = sizes.get(case, {})
            vf = t.get("vf_ms")
            vc = t.get("vc_ms")
            preproc = (vf - vc) if (vf is not None and vc is not None) else None
            rows.append([
                q, "tt", sf,
                "",                            # 4-thread prover (not run here)
                fmt(t.get("prover_s")),
                fmt(vf), fmt(vc), fmt(preproc),
                fmt(s.get("core_kb")),
                fmt(s.get("plan_kb")),
                fmt(s.get("total_kb")),
            ])
    return rows


# ── Poneglyph rows ──────────────────────────────────────────────────
def extract_poneglyph_json(log_path):
    """Pull the last JSON line whose `marker` is POENGLYPH_BENCH_JSON."""
    text = log_path.read_text(errors="replace")
    found = None
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("marker") == "POENGLYPH_BENCH_JSON":
            found = obj
    return found


def collect_poneglyph_rows():
    rows = []
    log_re = re.compile(r"^poneglyph_q(?P<q>\d+)_k(?P<k>\d+)\.log$")
    for log_path in sorted(RAW_DIR.glob("poneglyph_q*_k*.log")):
        m = log_re.match(log_path.name)
        if not m:
            continue
        q_str = m.group("q")
        k = int(m.group("k"))
        obj = extract_poneglyph_json(log_path)
        if obj is None:
            print(f"  skip {log_path.name}: no POENGLYPH_BENCH_JSON line", file=sys.stderr)
            continue
        bench = obj.get("bench", {})
        sf = PGN_SF_BY_K.get(q_str, {}).get(k)
        if sf is None:
            print(
                f"  skip {log_path.name}: unknown (q={q_str}, k={k})",
                file=sys.stderr,
            )
            continue
        prove_s = bench.get("prove_time_s")
        verify_s = bench.get("verify_time_s")
        proof_b = bench.get("proof_size_bytes")
        total_verifier_ms = verify_s * 1000 if verify_s is not None else None
        proof_kb = proof_b / 1024 if proof_b is not None else None

        rows.append([
            f"q{q_str}",
            "poneglyph",
            sf,
            "",                          # 4-thread prover (Poneglyph not threaded)
            fmt(prove_s),
            fmt(total_verifier_ms),
            "",                          # core verifier (not split for Poneglyph)
            "",                          # preprocessed verifier
            "",                          # proof size core (single proof, not split)
            "",                          # plan size
            fmt(proof_kb),
        ])
    return rows


# ── main ────────────────────────────────────────────────────────────
def sort_key(row):
    q = row[0] if row else ""
    system = row[1] if len(row) > 1 else ""
    sf = row[2] if len(row) > 2 else "0"
    m = re.match(r"q(\d+)$", q)
    n = int(m.group(1)) if m else 999
    sys_order = {"tt": 0, "poneglyph": 1}.get(system, 2)
    try:
        sf_val = float(sf)
    except ValueError:
        sf_val = 999
    return (n, sf_val, sys_order)


def main():
    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)

    tt_rows = collect_tt_rows()
    pgn_rows = collect_poneglyph_rows()
    all_rows = tt_rows + pgn_rows
    all_rows.sort(key=sort_key)

    with open(CSV_PATH, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(all_rows)

    pgn_log_count = len(list(RAW_DIR.glob("poneglyph_q*_k*.log")))
    print(f"Wrote {CSV_PATH}: {len(tt_rows)} tt rows, {len(pgn_rows)} poneglyph rows")
    print(f"Data sources: TT _pgn at SF={','.join(TT_SFS)}; {pgn_log_count} poneglyph logs")


if __name__ == "__main__":
    main()
