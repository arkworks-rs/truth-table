#!/usr/bin/env bash
# Full TPC-H benchmark sweep across scale factors and thread counts.
#
# Execution order (data-gen runs once per SF, before the first bench at that SF):
#
#   1. data-gen 0.01  → bench threads=1
#   2. data-gen 0.02  → bench threads=1
#   3. data-gen 0.04  → bench threads=1
#   4. data-gen 0.05  → bench threads=4, then threads=1
#   5. data-gen 0.1   → bench threads=4, then threads=1
#
# After each (SF, threads) sweep the shared divan/stats files are renamed:
#   benches.json      → benches_{SF}_{threads}.json
#   bench_stats.jsonl → bench_stats_{SF}_{threads}.jsonl
# Per-query stdout is saved to tpch_{SF}_{threads}_{query}.txt.
#
# Errors (verifier rejection, panic, etc.) are logged but never abort the sweep.
#
# Usage:
#   ./crates/tt-exec/benches/tpch/run_all.sh

set -uo pipefail   # no -e: we never abort on individual query failures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
mkdir -p "$RESULTS_DIR"

# ── query lists ─────────────────────────────────────────────────────
QUERIES_TT=(
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

QUERIES_PGN=(
    tpch_q1_pgn
    tpch_q3_pgn
    tpch_q5_pgn
    tpch_q8_pgn
    tpch_q9_pgn
    tpch_q18_pgn
)

ALL_QUERIES=("${QUERIES_TT[@]}" "${QUERIES_PGN[@]}")

# Shared output files that divan / the stats layer write to.
BENCHES_JSON="$RESULTS_DIR/benches.json"
BENCH_STATS_JSONL="$RESULTS_DIR/bench_stats.jsonl"

# ── helpers ─────────────────────────────────────────────────────────
data_gen() {
    local sf="$1"
    echo ""
    echo "=============================================="
    echo "  data-gen --scale $sf"
    echo "=============================================="
    # Clear the persisted proof cache — proofs are keyed by query name only
    # (not SF), so stale proofs from a previous SF would be reused otherwise.
    local proof_cache="$REPO_ROOT/artifacts/bench-proof-cache"
    if [[ -d "$proof_cache" ]]; then
        echo "  clearing proof cache: $proof_cache"
        rm -rf "$proof_cache"
    fi
    # --output-dir must point to bench-data (not test-data) so the bench
    # harness picks up the freshly generated parquet files.
    local bench_data="$REPO_ROOT/artifacts/bench-data"
    cargo run -p tt-exec --bin tt -- data-gen --scale "$sf" --output-dir "$bench_data" || true
}

run_one_sweep() {
    local sf="$1"
    local nthreads="$2"
    local tag="${sf}_${nthreads}"

    echo ""
    echo "──────────────────────────────────────────────"
    echo "  SF=$sf  RAYON_NUM_THREADS=$nthreads"
    echo "──────────────────────────────────────────────"

    # Remove stale shared files so this run starts clean.
    rm -f "$BENCHES_JSON" "$BENCH_STATS_JSONL"

    for q in "${ALL_QUERIES[@]}"; do
        local logfile="$RESULTS_DIR/tpch_${sf}_${nthreads}_${q}.txt"
        echo ">>> [SF=$sf, ${nthreads}t] $q"
        RAYON_NUM_THREADS="$nthreads" \
            cargo bench -p tt-exec --bench benches -- "tpch::${q}" \
            2>&1 | tee "$logfile" \
            || echo "  !! $q failed (continuing)"
        echo ""
    done

    # Rename shared outputs to tagged names.
    [[ -f "$BENCHES_JSON" ]]      && mv "$BENCHES_JSON"      "$RESULTS_DIR/benches_${tag}.json"
    [[ -f "$BENCH_STATS_JSONL" ]] && mv "$BENCH_STATS_JSONL" "$RESULTS_DIR/bench_stats_${tag}.jsonl"

    echo "  → saved benches_${tag}.json, bench_stats_${tag}.jsonl"
}

# ── main pipeline ───────────────────────────────────────────────────
echo "=== TPC-H full benchmark sweep ==="
echo "Queries: ${#ALL_QUERIES[@]}"
echo "Results dir: $RESULTS_DIR"
echo ""

# SF 0.01 — 1 thread
data_gen 0.01
run_one_sweep 0.01 1

# SF 0.02 — 1 thread
data_gen 0.02
run_one_sweep 0.02 1

# SF 0.04 — 1 thread
data_gen 0.04
run_one_sweep 0.04 1

# SF 0.05 — 4 threads first, then 1 thread
data_gen 0.05
run_one_sweep 0.05 4
run_one_sweep 0.05 1

# SF 0.1 — 4 threads first, then 1 thread
data_gen 0.1
run_one_sweep 0.1 4
run_one_sweep 0.1 1

echo ""
echo "=== Done ==="
