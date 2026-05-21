#!/usr/bin/env bash
# Run TruthTable on the regular TPC-H queries (the `_tt` bench variants),
# across the full (scale-factor, threads) matrix.
#
# Execution order (data-gen runs once per SF, before the first bench at that SF):
#
#   1. data-gen 0.05  → bench threads=4, then threads=1
#   2. data-gen 0.1   → bench threads=4, then threads=1
#
# SF=0.01/0.02/0.04 are not run here — those scale factors only matter for
# the head-to-head against PoneglyphDB, which `run_pgn.sh` covers via the
# `_pgn` query variants at exactly those SFs.
#
# After each (SF, threads) sweep the shared divan / stats files are renamed:
#   benches.json      → benches_tt_{SF}_{threads}.json
#   bench_stats.jsonl → bench_stats_tt_{SF}_{threads}.jsonl
# Per-query stdout is saved to tpch_tt_{SF}_{threads}_{query}.txt.
#
# The Poneglyph-style `_pgn` variants are NOT run here — see run_pgn.sh.
#
# Errors (verifier rejection, panic, etc.) are logged but never abort the sweep.
#
# Usage:
#   ./tt-results/scripts/run_tt_tpch.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
mkdir -p "$RESULTS_DIR"

QUERIES=(
    tpch_q1_tt
    tpch_q2_tt
    tpch_q3_tt
    tpch_q4_tt
    tpch_q5_tt
    tpch_q6_tt
    tpch_q7_tt
    tpch_q8_tt
    tpch_q9_tt
    tpch_q10_tt
    tpch_q12_tt
    tpch_q14_tt
    tpch_q15_tt
    tpch_q17_tt
    tpch_q18_tt
    tpch_q19_tt
    tpch_q20_tt
)

BENCHES_JSON="$RESULTS_DIR/benches.json"
BENCH_STATS_JSONL="$RESULTS_DIR/bench_stats.jsonl"

data_gen() {
    local sf="$1"
    echo ""
    echo "=============================================="
    echo "  data-gen --scale $sf"
    echo "=============================================="
    # Proofs are cached by query name only (not SF), so wipe the cache between SFs.
    local proof_cache="$REPO_ROOT/artifacts/bench-proof-cache"
    [[ -d "$proof_cache" ]] && rm -rf "$proof_cache"
    local bench_data="$REPO_ROOT/artifacts/bench-data"
    cargo run -p tt-exec --bin tt -- data-gen --scale "$sf" --output-dir "$bench_data" || true
}

run_one_sweep() {
    local sf="$1"
    local nthreads="$2"
    local tag="${sf}_${nthreads}"

    echo ""
    echo "──────────────────────────────────────────────"
    echo "  TT TPC-H  SF=$sf  RAYON_NUM_THREADS=$nthreads"
    echo "──────────────────────────────────────────────"

    rm -f "$BENCHES_JSON" "$BENCH_STATS_JSONL"

    for q in "${QUERIES[@]}"; do
        local logfile="$RESULTS_DIR/tpch_tt_${sf}_${nthreads}_${q}.txt"
        echo ">>> [SF=$sf, ${nthreads}t] $q"
        RAYON_NUM_THREADS="$nthreads" \
            cargo bench -p tt-exec --bench benches -- "tpch::${q}" \
            2>&1 | tee "$logfile" \
            || echo "  !! $q failed (continuing)"
        echo ""
    done

    [[ -f "$BENCHES_JSON" ]]      && mv "$BENCHES_JSON"      "$RESULTS_DIR/benches_tt_${tag}.json"
    [[ -f "$BENCH_STATS_JSONL" ]] && mv "$BENCH_STATS_JSONL" "$RESULTS_DIR/bench_stats_tt_${tag}.jsonl"

    echo "  → saved benches_tt_${tag}.json, bench_stats_tt_${tag}.jsonl"
}

echo "=== TT TPC-H full benchmark sweep ==="
echo "Queries: ${#QUERIES[@]}"
echo "Results dir: $RESULTS_DIR"

data_gen 0.05
run_one_sweep 0.05 4
run_one_sweep 0.05 1

data_gen 0.1
run_one_sweep 0.1 4
run_one_sweep 0.1 1

echo ""
echo "=== TT TPC-H sweep complete ==="
