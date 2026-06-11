#!/usr/bin/env python3
"""Parse a third-party-bench log into structured JSON.

Usage:
  parse_bench_output.py <bench> <log_path> <json_out>

Where <bench> is one of: sxt_proof_of_sql, qedb, truth_table.

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


# ── sxt_proof_of_sql ────────────────────────────────────────────────
#
# Emits, per query:
#   parquet_dir: artifact/size_<pow>
#   parquet: <path>                                        (1 or more lines)
#   <scheme>,<query>,<table_size>,<prove_ms>,<verify_ms>,<proof_bytes>,<iter>
#   prove_ms: <..> verify_ms: <..> proof_bytes: <..> iteration: <..>
#   Number of query results: <N>
#   ----------------------------------------
#
# Header: BLITZAR_BACKEND=<backend>, iterations: <N>, table_sizes: [..]

def parse_sxt_proof_of_sql(text: str) -> dict:
    config = _thread_config()
    m = re.search(r"^BLITZAR_BACKEND=(\S+)", text, re.M)
    if m:
        config["blitzar_backend"] = m.group(1)
    m = re.search(r"^iterations:\s*(\d+)", text, re.M)
    if m:
        config["iterations"] = int(m.group(1))
    m = re.search(r"^table_sizes:\s*\[([^\]]*)\]", text, re.M)
    if m:
        config["table_pows"] = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]

    # CSV summary line: scheme,query,table_size,prove_ms,verify_ms,proof_bytes,iter
    csv_re = re.compile(
        r"^([A-Za-z][A-Za-z0-9_]*),"
        r"([^,\n]+?),"          # query name (may contain spaces)
        r"(\d+),(\d+),(\d+),(\d+),(\d+)\s*$",
        re.M,
    )
    nqr_re = re.compile(r"^Number of query results:\s*(\d+)\s*$", re.M)

    # Split the text into chunks per query using the separator line.
    chunks = re.split(r"^-{5,}\s*$", text, flags=re.M)

    # Track (pow → table_size) as we scan — each `table_size:` or
    # `parquet_dir:` line establishes the current pow context.
    results = []
    current_pow = None
    current_size = None
    for chunk in chunks:
        # Update context from any header lines inside the chunk.
        for line in chunk.splitlines():
            m = re.match(r"\s*parquet_dir:\s*artifact/size_(\d+)", line)
            if m:
                current_pow = int(m.group(1))
            m = re.match(r"\s*table_size:\s*(\d+)", line)
            if m:
                current_size = int(m.group(1))

        csv = csv_re.search(chunk)
        if not csv:
            continue
        nqr = nqr_re.search(chunk)
        parquet_paths = re.findall(r"^parquet:\s*(\S.*?)\s*$", chunk, re.M)
        parquet_paths = [p for p in parquet_paths if p != "none"]

        results.append({
            "pow": current_pow,
            "table_size": int(csv.group(3)),
            "scheme": csv.group(1),
            "query": csv.group(2).strip(),
            "prove_ms": int(csv.group(4)),
            "verify_ms": int(csv.group(5)),
            "proof_bytes": int(csv.group(6)),
            "iteration": int(csv.group(7)),
            "num_query_results": int(nqr.group(1)) if nqr else None,
            "parquet_paths": parquet_paths,
        })

    return {"bench": "sxt_proof_of_sql", "config": config, "results": results}


# ── qedb ─────────────────────────────────────────────────────────────
#
# Emits, per (pow, query):
#   pow: <pow> query: <name>
#   prove_ms: <..>
#   verify_ms: <..>
#   proof_bytes: <..>
#   ----------------------------------------

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
        for field in ("prove_ms", "verify_ms", "proof_bytes"):
            m = re.search(rf"^{field}:\s*(\d+)\s*$", chunk, re.M)
            if m:
                rec[field] = int(m.group(1))
        results.append(rec)

    return {"bench": "qedb", "config": config, "results": results}


# ── truth_table ──────────────────────────────────────────────────────
#
# Emits, per (pow, query):
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
    # `curve: <name>` is emitted once at the top of the bench by the
    # `tt-exec::backend::BACKEND_NAME` constant. Default to "bn254" if the
    # bench predates the tag (older logs).
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

        # Single-value fields: setup, prove, proof size, verify.
        for field in ("setup_ms", "prove_ms", "verify_ms", "proof_bytes"):
            m = re.search(rf"^{field}:\s*(\d+)\s*$", chunk, re.M)
            if m:
                rec[field] = int(m.group(1))

        # Multi-value fields: preprocess (0–2) and commit (1–2 for joins).
        preprocess = [int(x) for x in re.findall(r"^preprocess_ms:\s*(\d+)\s*$", chunk, re.M)]
        commit = [int(x) for x in re.findall(r"^commit_ms:\s*(\d+)\s*$", chunk, re.M)]
        if preprocess:
            rec["preprocess_ms"] = preprocess
        if commit:
            rec["commit_ms"] = commit

        results.append(rec)

    return {"bench": "truth_table", "config": config, "results": results}


# ── main ─────────────────────────────────────────────────────────────
PARSERS = {
    "sxt_proof_of_sql": parse_sxt_proof_of_sql,
    "qedb": parse_qedb,
    "truth_table": parse_truth_table,
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
