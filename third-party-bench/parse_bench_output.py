#!/usr/bin/env python3
"""Parse a third-party-bench log into structured JSON.

Usage:
  parse_bench_output.py <bench> <log_path> <json_out>

Where <bench> is one of: sxt_proof_of_sql, qedb, truth_table, baseline,
baseline_tpch, zkvm.

Each parser is tolerant of extra noise (cargo messages, tracing output, etc.):
it only matches the specific println! lines each bench emits, and ignores the
rest.
"""

import json
import os
import re
import sys
from pathlib import Path


def _thread_config() -> dict:
    """Read num_threads from TT_BENCH_NUM_THREADS (preferred) or RAYON_NUM_THREADS."""
    for var in ("TT_BENCH_NUM_THREADS", "RAYON_NUM_THREADS"):
        v = os.environ.get(var)
        if v and v.isdigit():
            return {"num_threads": int(v)}
    return {}


# sxt_proof_of_sql emits, per query:
#   parquet_dir: artifact/size_<pow>
#   parquet: <path>                                        (1 or more lines)
#   <scheme>,<query>,<table_size>,<prove_ms>,<verify_ms>,<proof_bytes>,<iter>
#   prove_ms: <..> verify_ms: <..> proof_bytes: <..> iteration: <..>
#   Number of query results: <N>
#   ----------------------------------------
#
# Header: BLITZAR_BACKEND=<backend>, iterations: <N>, table_sizes: [..]

# Per-query fields any bench may print as `<name>: <number>`.
METRIC_FIELDS = (
    "setup_ms",
    "params_bytes",
    "pk_bytes",
    "vk_bytes",
    "keygen_ms",
    "preprocess_ms",
    "commit_ms",
    "commitment_bytes",
    "prove_ms",
    "proof_bytes",
    "verify_ms",
    "execute_ms",
    "result_rows",
    "public_inputs",
    "cycles",
)


def _numeric_fields(chunk: str, fields=METRIC_FIELDS) -> dict:
    rec = {}
    for field in fields:
        m = re.search(rf"^{field}:\s*([\d.]+)\s*$", chunk, re.M)
        if m:
            rec[field] = float(m.group(1)) if "." in m.group(1) else int(m.group(1))
    return rec


def parse_sxt_proof_of_sql(text: str) -> dict:
    parsed = parse_qedb(text)
    parsed["bench"] = "sxt_proof_of_sql"
    return parsed


# qedb emits, per (pow, query), `pow: <pow> query: <name>` and then
# METRIC_FIELDS lines, ending with a dashed separator.

def parse_poneglyph(text: str) -> dict:
    """Poneglyph's micro bench prints QEDB's lines, plus the circuit variant
    (`faithful` or `fixed`, whose rows get System "Poneglyph (data-independent)")."""
    parsed = parse_qedb(text)
    chunks = [c for c in re.split(r"^-{5,}\s*$", text, flags=re.M) if re.search(r"^pow:", c, re.M)]
    for rec, chunk in zip(parsed["results"], chunks):
        m = re.search(r"variant:\s*(\S+)", chunk)
        if m:
            rec["variant"] = m.group(1)
            if m.group(1) == "fixed":
                rec["system"] = "Poneglyph (data-independent)"
    parsed["bench"] = "poneglyph"
    return parsed


def parse_poneglyph_tpch(text: str) -> dict:
    """Poneglyph's data-independent TPC-H circuits: one chunk per
    `sf: <sf> query: q<n> variant: fixed` with the micro bench's metric lines
    and the circuit degree `k`."""
    head_re = re.compile(r"^sf:\s*(\S+)\s+query:\s*q(\d+)\s+variant:\s*(\S+)", re.M)
    results = []
    for chunk in re.split(r"^-{5,}\s*$", text, flags=re.M):
        head = head_re.search(chunk)
        if not head:
            continue
        rec = {
            "sf": float(head.group(1)),
            "query": int(head.group(2)),
            "variant": head.group(3),
            "system": "Poneglyph (data-independent)",
        }
        rec.update(_numeric_fields(chunk, METRIC_FIELDS + ("k",)))
        results.append(rec)
    return {"bench": "poneglyph_tpch", "config": _thread_config(), "results": results}


def parse_qedb(text: str) -> dict:
    config = _thread_config()
    m = re.search(r"^table_sizes:\s*\[([^\]]*)\]", text, re.M)
    if m:
        config["table_pows"] = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]

    chunks = re.split(r"^-{5,}\s*$", text, flags=re.M)
    results = []
    head_re = re.compile(r"^pow:\s*(\d+)\s+query:\s*(\S+)", re.M)
    for chunk in chunks:
        head = head_re.search(chunk)
        if not head:
            continue
        pow_val = int(head.group(1))
        query = head.group(2)
        rec = {"pow": pow_val, "table_size": 1 << pow_val, "query": query}
        rec.update(_numeric_fields(chunk))
        results.append(rec)

    return {"bench": "qedb", "config": config, "results": results}


# truth_table emits, per (pow, query):
#   pow: <pow> query: <name> parquet_rows: <R> log_size: <L>
#   setup_ms: <..>           (only on cache miss)
#   preprocess_ms: <..>      (0, 1, or 2 — one per preprocessed parquet)
#   commit_ms: <..>          (1 for normal, 2 for joins)
#   prove_ms: <..>
#   proof_bytes: <..>
#   verify_ms: <..>
#   ----------------------------------------

def parse_truth_table(text: str) -> dict:
    config = _thread_config()
    m = re.search(r"^table_sizes:\s*\[([^\]]*)\]", text, re.M)
    if m:
        config["table_pows"] = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
    # The bench prints `curve: <name>` once at the top
    # (`tt-exec::backend::BACKEND_NAME`). A log without it is bn254.
    m = re.search(r"^curve:\s*(\S+)\s*$", text, re.M)
    curve = m.group(1) if m else "bn254"
    config["curve"] = curve

    chunks = re.split(r"^-{5,}\s*$", text, flags=re.M)
    results = []
    head_re = re.compile(
        r"^pow:\s*(\d+)\s+query:\s*(\S+)\s+parquet_rows:\s*(\d+)\s+log_size:\s*(\d+)",
        re.M,
    )
    for chunk in chunks:
        head = head_re.search(chunk)
        if not head:
            continue
        rec = {
            "pow": int(head.group(1)),
            "table_size": 1 << int(head.group(1)),
            "query": head.group(2),
            "parquet_rows": int(head.group(3)),
            "log_size": int(head.group(4)),
            "curve": curve,
        }

        rec.update(_numeric_fields(chunk))
        results.append(rec)

    return {"bench": "truth_table", "config": config, "results": results}


# baseline emits, per (pow, query), medians in fractional milliseconds:
#   pow: <pow> query: <name> rows: <R>[,<R2>]
#   commit_ms: <..>
#   commitment_bytes: <..>
#   prove_ms: <..>
#   proof_bytes: <..>
#   verify_ms: <..>
#   execute_ms: <..>
#   result_rows: <..>
#   ----------------------------------------
#
# Header: threads: <N>, iterations: <N>, table_sizes: [..]

def parse_baseline(text: str) -> dict:
    config = _thread_config()
    m = re.search(r"^threads:\s*(\d+)", text, re.M)
    if m:
        config["num_threads"] = int(m.group(1))
    m = re.search(r"^iterations:\s*(\d+)", text, re.M)
    if m:
        config["iterations"] = int(m.group(1))
    m = re.search(r"^table_sizes:\s*\[([^\]]*)\]", text, re.M)
    if m:
        config["table_pows"] = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]

    chunks = re.split(r"^-{5,}\s*$", text, flags=re.M)
    results = []
    head_re = re.compile(r"^pow:\s*(\d+)\s+query:\s*(\S+)\s+rows:\s*([\d,]+)", re.M)
    for chunk in chunks:
        head = head_re.search(chunk)
        if not head:
            continue
        rec = {
            "pow": int(head.group(1)),
            "table_size": 1 << int(head.group(1)),
            "query": head.group(2),
            "parquet_rows": [int(x) for x in head.group(3).split(",")],
        }
        for field in ("commit_ms", "prove_ms", "verify_ms", "execute_ms"):
            m = re.search(rf"^{field}:\s*([\d.]+)\s*$", chunk, re.M)
            if m:
                rec[field] = float(m.group(1))
        for field in ("commitment_bytes", "proof_bytes", "result_rows"):
            m = re.search(rf"^{field}:\s*(\d+)\s*$", chunk, re.M)
            if m:
                rec[field] = int(m.group(1))
        results.append(rec)

    return {"bench": "baseline", "config": config, "results": results}


# baseline_tpch emits one `key=value` line per committed table and per query
# (see benches/baseline_tpch.rs), after a `threads:`/`iterations:` header.

def parse_baseline_tpch(text: str) -> dict:
    config = _thread_config()
    m = re.search(r"^threads:\s*(\d+)", text, re.M)
    if m:
        config["num_threads"] = int(m.group(1))
    m = re.search(r"^iterations:\s*(\d+)", text, re.M)
    if m:
        config["iterations"] = int(m.group(1))

    def fields(line):
        rec = {}
        for key, value in re.findall(r"(\w+)=(\S+)", line):
            if key in ("variant", "name", "sf"):
                rec[key] = value
            elif "." in value:
                rec[key] = float(value)
            else:
                rec[key] = int(value)
        return rec

    tables = [fields(line) for line in re.findall(r"^table (.*)$", text, re.M)]
    results = [fields(line) for line in re.findall(r"^query (.*)$", text, re.M)]
    return {"bench": "baseline_tpch", "config": config, "tables": tables, "results": results}


# zkvm (zkvm/script: the `micro` and `tpch` binaries) emits a `prover:`/
# `threads:`/`setup_ms:` header, then `key=value` lines: one `query ...` per
# run and proof mode, and (TPC-H) one `table ...` per committed table.

def parse_zkvm(text: str) -> dict:
    config = _thread_config()
    m = re.search(r"^prover:\s*(\S+)", text, re.M)
    if m:
        config["prover"] = m.group(1)
    m = re.search(r"^setup_ms:\s*([\d.]+)", text, re.M)
    if m:
        config["setup_ms"] = float(m.group(1))

    def fields(line):
        rec = {}
        for key, value in re.findall(r"(\w+)=(\S+)", line):
            if key in ("q", "mode", "variant", "sf", "name"):
                rec["query" if key == "q" else key] = value
            elif "." in value:
                rec[key] = float(value)
            else:
                rec[key] = int(value)
        return rec

    results = [fields(line) for line in re.findall(r"^query (.*)$", text, re.M)]
    # A resumed suite commits its tables again; keep each table's first line.
    tables = {}
    for line in re.findall(r"^table (.*)$", text, re.M):
        rec = fields(line)
        tables.setdefault((rec["sf"], rec["name"]), rec)
    failures = [fields(line) for line in re.findall(r"^failed (.*)$", text, re.M)]
    return {
        "bench": "zkvm",
        "config": config,
        "tables": list(tables.values()),
        "results": results,
        "failures": failures,
    }


PARSERS = {
    "sxt_proof_of_sql": parse_sxt_proof_of_sql,
    "qedb": parse_qedb,
    "poneglyph": parse_poneglyph,
    "poneglyph_tpch": parse_poneglyph_tpch,
    "truth_table": parse_truth_table,
    "baseline": parse_baseline,
    "baseline_tpch": parse_baseline_tpch,
    "zkvm": parse_zkvm,
}


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <bench> <log_path> <json_out>", file=sys.stderr)
        sys.exit(2)
    bench, log_path, json_out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])

    parser = PARSERS.get(bench)
    if parser is None:
        print(f"Unknown bench: {bench}. Known: {list(PARSERS)}", file=sys.stderr)
        sys.exit(2)

    if not log_path.exists():
        print(f"Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    parsed = parser(log_path.read_text())
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(parsed, indent=2) + "\n")
    print(f"Wrote {json_out}: {len(parsed['results'])} results")


if __name__ == "__main__":
    main()
