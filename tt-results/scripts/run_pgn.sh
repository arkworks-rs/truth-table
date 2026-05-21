#!/usr/bin/env bash
# Poneglyph comparison sweep — runs BOTH:
#   (A) TruthTable on the Poneglyph-style `_pgn` query variants
#   (B) PoneglyphDB on its own KZG queries (via tt-poneglyph-bench)
# at matching dataset sizes so the two systems can be compared head-to-head.
#
# Dataset / SF / k mapping (Q3 included — its circuit needs k≥16 in practice):
#   k=16  ↔  60K rows   ↔  TPC-H SF=0.01
#   k=17  ↔  120K rows  ↔  TPC-H SF=0.02
#   k=18  ↔  240K rows  ↔  TPC-H SF=0.04
#
# TruthTable runs at threads=1 to match PoneglyphDB's single-threaded prover
# (`RAYON_NUM_THREADS=1`), so the two `prover time 1thread (s)` columns are
# directly comparable.
#
# Outputs to tt-results/raw/:
#   (A) benches_pgn_{SF}_1.json, bench_stats_pgn_{SF}_1.jsonl,
#       tpch_pgn_{SF}_1_{query}.txt
#   (B) poneglyph_q{N}_k{K}.log
#
# Known upstream limitation (PoneglyphDB Q18 at k=17/18): proof verification
# returns ConstraintSystemFailure. The sweep records the prove time / proof
# size anyway and marks verify_ok: false in the log.
#
# Usage:
#   ./tt-results/scripts/run_pgn.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
mkdir -p "$RESULTS_DIR"

# ───────────────────────────────────────────────────────────────────
# Part A — TruthTable on _pgn TPC-H variants
# ───────────────────────────────────────────────────────────────────
TT_QUERIES_PGN=(
    tpch_q1_pgn
    tpch_q3_pgn
    tpch_q5_pgn
    tpch_q8_pgn
    tpch_q9_pgn
    tpch_q18_pgn
)

# (SF) sweep for TT-on-pgn — matches PoneglyphDB's k=16/17/18 dataset sizes.
TT_SFS=(0.01 0.02 0.04)

BENCHES_JSON="$RESULTS_DIR/benches.json"
BENCH_STATS_JSONL="$RESULTS_DIR/bench_stats.jsonl"

data_gen() {
    local sf="$1"
    echo ""
    echo "=============================================="
    echo "  data-gen --scale $sf"
    echo "=============================================="
    local proof_cache="$REPO_ROOT/artifacts/bench-proof-cache"
    [[ -d "$proof_cache" ]] && rm -rf "$proof_cache"
    local bench_data="$REPO_ROOT/artifacts/bench-data"
    cargo run -p tt-exec --bin tt -- data-gen --scale "$sf" --output-dir "$bench_data" || true
}

run_tt_pgn_sweep() {
    local sf="$1"
    local nthreads=1
    local tag="${sf}_${nthreads}"

    echo ""
    echo "──────────────────────────────────────────────"
    echo "  TT-on-pgn  SF=$sf  RAYON_NUM_THREADS=$nthreads"
    echo "──────────────────────────────────────────────"

    rm -f "$BENCHES_JSON" "$BENCH_STATS_JSONL"

    for q in "${TT_QUERIES_PGN[@]}"; do
        local logfile="$RESULTS_DIR/tpch_pgn_${sf}_${nthreads}_${q}.txt"
        echo ">>> [SF=$sf, ${nthreads}t] $q"
        RAYON_NUM_THREADS="$nthreads" \
            cargo bench -p tt-exec --bench benches -- "tpch::${q}" \
            2>&1 | tee "$logfile" \
            || echo "  !! $q failed (continuing)"
        echo ""
    done

    [[ -f "$BENCHES_JSON" ]]      && mv "$BENCHES_JSON"      "$RESULTS_DIR/benches_pgn_${tag}.json"
    [[ -f "$BENCH_STATS_JSONL" ]] && mv "$BENCH_STATS_JSONL" "$RESULTS_DIR/bench_stats_pgn_${tag}.jsonl"

    echo "  → saved benches_pgn_${tag}.json, bench_stats_pgn_${tag}.jsonl"
}

echo "=== PGN comparison: TruthTable on _pgn variants ==="
for sf in "${TT_SFS[@]}"; do
    data_gen "$sf"
    run_tt_pgn_sweep "$sf"
done

# ───────────────────────────────────────────────────────────────────
# Part B — PoneglyphDB on its own KZG queries
# ───────────────────────────────────────────────────────────────────
PGN_BIN="$REPO_ROOT/target/release/tt-poneglyph-bench"

echo ""
echo "=== PGN comparison: PoneglyphDB system ==="
echo "Building tt-poneglyph-bench"
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build -p tt-poneglyph-bench --release

PGN_QUERIES=(
    "1:16,17,18"
    "3:16,17,18"
    "5:16,17,18"
    "8:16,17,18"
    "9:16,17,18"
    "18:16,17,18"
)

run_pgn_one() {
    local query="$1"
    local k="$2"
    local log="$RESULTS_DIR/poneglyph_q${query}_k${k}.log"

    echo ""
    echo "──────────────────────────────────────────────"
    echo "  PoneglyphDB Q${query}  k=${k}"
    echo "──────────────────────────────────────────────"

    # 32 MiB stack for the deeper circuits; pin to 1 thread so the prove time
    # is comparable to TT's `prover time 1thread (s)` column.
    RUST_MIN_STACK=33554432 \
    RAYON_NUM_THREADS=1 \
        "$PGN_BIN" --query "$query" --k "$k" \
        2>&1 | tee "$log" \
        || echo "  !! q${query} k=${k} failed (continuing)"
}

for entry in "${PGN_QUERIES[@]}"; do
    query="${entry%:*}"
    ks="${entry#*:}"
    IFS=',' read -r -a k_list <<< "$ks"
    for k in "${k_list[@]}"; do
        run_pgn_one "$query" "$k"
    done
done

echo ""
echo "=== PGN comparison sweep complete ==="
echo "TT-on-pgn logs:    $RESULTS_DIR/tpch_pgn_*.txt"
echo "TT-on-pgn data:    $RESULTS_DIR/benches_pgn_*.json + bench_stats_pgn_*.jsonl"
echo "PoneglyphDB logs:  $RESULTS_DIR/poneglyph_q*_k*.log"
