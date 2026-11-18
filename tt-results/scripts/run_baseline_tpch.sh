#!/usr/bin/env bash
# Run the no-proof baseline (third-party-bench/benches/baseline_tpch.rs) on the
# `_tt` and `_pgn` TPC-H queries at every scale factor of the TruthTable
# sweeps, once per thread count, pinned to CPUs 0..t-1 (distinct physical
# cores on the bench machine; check `lscpu -e` elsewhere). The bench
# generates its own tables under third-party-bench/artifact/tpch/ on first use.
#
# Outputs to tt-results/raw/:
#   baseline_tpch_<t>.log   — bench stdout
#   baseline_tpch_<t>.json  — parsed results, read by parse_baseline_tpch.py
#
# Usage:
#   ./tt-results/scripts/run_baseline_tpch.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
TPB_DIR="$REPO_ROOT/third-party-bench"
PARSER="$TPB_DIR/parse_bench_output.py"
THREADS=(1 4)

mkdir -p "$RESULTS_DIR"

# Build unpinned; only the measured runs are pinned.
(cd "$TPB_DIR" && cargo bench --bench baseline_tpch --no-run 2>&1)

for t in "${THREADS[@]}"; do
    log="$RESULTS_DIR/baseline_tpch_${t}.log"
    echo ""
    echo "=============================================="
    echo "  cargo bench --bench baseline_tpch  (threads=$t, CPUs 0-$((t - 1)))"
    echo "=============================================="
    (
        cd "$TPB_DIR"
        CUDA_VISIBLE_DEVICES="" RAYON_NUM_THREADS="$t" taskset -c "0-$((t - 1))" \
            cargo bench --bench baseline_tpch 2>&1
    ) | tee "$log"
    TT_BENCH_NUM_THREADS="$t" \
        python3 "$PARSER" baseline_tpch "$log" "$RESULTS_DIR/baseline_tpch_${t}.json" \
        || echo "  !! parser failed for baseline_tpch ($t threads)"
done

echo ""
echo "=== baseline TPC-H sweep complete ==="
