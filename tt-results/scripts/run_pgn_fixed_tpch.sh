#!/usr/bin/env bash
# Run PoneglyphDB's data-independent TPC-H circuits
# (third-party-bench/benches/poneglyph_tpch.rs) on the six `_pgn` queries at
# SF 0.01, 0.02 and 0.04, on one thread pinned to CPU 0. Each circuit's result
# is checked against DataFusion's first, so the reference CSVs must exist:
#   (cd third-party-bench && cargo run --release --bin tpch_reference)
# PGN_SFS and PGN_QUERIES narrow the sweep (comma-separated).
#
# Outputs to tt-results/raw/:
#   third_party_poneglyph_tpch.log   — bench stdout
#   third_party_poneglyph_tpch.json  — parsed results, read by parse_pgn.py
#
# Usage:
#   ./tt-results/scripts/run_pgn_fixed_tpch.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
TPB_DIR="$REPO_ROOT/third-party-bench"
LOG="$RESULTS_DIR/third_party_poneglyph_tpch.log"

mkdir -p "$RESULTS_DIR"

# Build unpinned; only the measured run is pinned.
(cd "$TPB_DIR" && cargo bench --bench poneglyph_tpch --no-run 2>&1 | tail -2) || exit 1

(
    cd "$TPB_DIR"
    CUDA_VISIBLE_DEVICES="" RAYON_NUM_THREADS=1 taskset -c 0 \
        cargo bench --bench poneglyph_tpch 2>&1
) | tee "$LOG"
TT_BENCH_NUM_THREADS=1 \
    python3 "$TPB_DIR/parse_bench_output.py" poneglyph_tpch "$LOG" \
    "$RESULTS_DIR/third_party_poneglyph_tpch.json" \
    || echo "  !! parser failed for poneglyph_tpch"

echo ""
echo "=== data-independent Poneglyph TPC-H sweep complete ==="
