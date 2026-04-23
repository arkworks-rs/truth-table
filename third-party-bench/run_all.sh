#!/usr/bin/env bash
# Run all third-party bench comparisons and emit structured JSON results.
#
# Steps:
#   1. Run each bench (sxt_proof_of_sql, qedb, truth_table), teeing stdout to
#      a log file under tt-results/raw/. Existing third-party-bench/artifact/
#      contents are reused (sxt generates parquet files that qedb + truth_table
#      read, so wiping would force a full regeneration).
#   2. Parse each log into a JSON file via parse_bench_output.py.
#
# Usage:
#   ./third-party-bench/run_all.sh

set -uo pipefail   # no -e: we never abort on individual bench failures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
PARSER="$SCRIPT_DIR/parse_bench_output.py"

mkdir -p "$RESULTS_DIR"

BENCHES=(sxt_proof_of_sql qedb truth_table)

# Pin every bench to 1 rayon thread so reported prover/verifier numbers match
# the `num_threads: 1` stamp the parser writes into the JSON. Without this,
# rayon defaults to all cores and the "threads=1" column in micro.csv lies.
NUM_THREADS=1

# The Join and Join_PK_FK parquets now share a deterministic PK/FK row shape
# written by sxt's bench. Wipe stale artifacts so downstream truth_table runs
# don't read the old random-data Join parquets or a mismatched preprocessed/oracle
# pair. Leaves Filter/Aggregate/Limit artifacts alone.
ARTIFACT_ROOT="$SCRIPT_DIR/artifact"
if [[ -d "$ARTIFACT_ROOT" ]]; then
    find "$ARTIFACT_ROOT" -type d \( -name Join -o -name Join_PK_FK \) -prune -print0 \
        | xargs -0 -I {} rm -rf {}
fi

run_bench() {
    local bench="$1"
    local log="$RESULTS_DIR/third_party_${bench}.log"

    echo ""
    echo "=============================================="
    echo "  cargo bench --bench $bench"
    echo "=============================================="

    (
        cd "$SCRIPT_DIR"
        RAYON_NUM_THREADS="$NUM_THREADS" \
            cargo bench --bench "$bench" 2>&1
    ) | tee "$log"

    echo ""
    echo "  → log: $log"

    TT_BENCH_NUM_THREADS="$NUM_THREADS" \
        python3 "$PARSER" "$bench" "$log" "$RESULTS_DIR/third_party_${bench}.json" \
        || echo "  !! parser failed for $bench"
}

for b in "${BENCHES[@]}"; do
    run_bench "$b"
done

echo ""
echo "=== Refreshing micro.csv + figures ==="
python3 "$REPO_ROOT/tt-results/update_micro_csv.py" \
    || echo "  !! update_micro_csv.py failed"
python3 "$REPO_ROOT/tt-results/tt-scripts/plot_micro.py" \
    || echo "  !! plot_micro.py failed"

echo ""
echo "=== Done ==="
echo "Results: $RESULTS_DIR/third_party_*.json"
echo "CSV:     $REPO_ROOT/tt-results/tidy/micro.csv"
echo "Figures: $REPO_ROOT/tt-results/figures/micro_*.pdf"
