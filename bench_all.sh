#!/usr/bin/env bash
# Master benchmark pipeline: run → parse → plot for every suite.
#
# Stages (each delegates to the corresponding tt-results/scripts/*_all.sh):
#   1. run_all.sh    — execute TT TPC-H, Poneglyph comparison, and micro sweeps
#   2. parse_all.sh  — rebuild tidy/{tpch,tpch_pgn,micro}.csv from raw outputs
#   3. plot_all.sh   — render figures/{tpch_tt,tpch_pgn,micro}_*.pdf
#
# Each stage tolerates failures in individual sub-scripts.
#
# Usage:
#   ./bench_all.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$REPO_ROOT/tt-results/scripts"

echo "============================================================"
echo " STAGE 1/3 — run_all.sh"
echo "============================================================"
"$SCRIPTS/run_all.sh"

echo ""
echo "============================================================"
echo " STAGE 2/3 — parse_all.sh"
echo "============================================================"
"$SCRIPTS/parse_all.sh"

echo ""
echo "============================================================"
echo " STAGE 3/3 — plot_all.sh"
echo "============================================================"
"$SCRIPTS/plot_all.sh"

echo ""
echo "=== bench_all.sh complete ==="
echo "CSVs:    $REPO_ROOT/tt-results/tidy/"
echo "Figures: $REPO_ROOT/tt-results/figures/"
