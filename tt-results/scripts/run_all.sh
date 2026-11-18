#!/usr/bin/env bash
# Run-and-dump every benchmark suite: TT TPC-H, Poneglyph comparison, micro,
# the baseline on TPC-H, the SP1 zkVM.
#
# Failures in one suite don't abort the others.
#
# Usage:
#   ./tt-results/scripts/run_all.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "########################################"
echo "# 1/6  run_tt_tpch.sh"
echo "########################################"
"$SCRIPT_DIR/run_tt_tpch.sh" || echo "  !! run_tt_tpch.sh failed (continuing)"

echo ""
echo "########################################"
echo "# 2/6  run_pgn.sh"
echo "########################################"
"$SCRIPT_DIR/run_pgn.sh" || echo "  !! run_pgn.sh failed (continuing)"

echo ""
echo "########################################"
echo "# 3/6  run_micro.sh"
echo "########################################"
"$SCRIPT_DIR/run_micro.sh" || echo "  !! run_micro.sh failed (continuing)"

echo ""
echo "########################################"
echo "# 4/6  run_tt_tpch_optall.sh"
echo "########################################"
"$SCRIPT_DIR/run_tt_tpch_optall.sh" || echo "  !! run_tt_tpch_optall.sh failed (continuing)"

echo ""
echo "########################################"
echo "# 5/6  run_baseline_tpch.sh"
echo "########################################"
"$SCRIPT_DIR/run_baseline_tpch.sh" || echo "  !! run_baseline_tpch.sh failed (continuing)"

echo ""
echo "########################################"
echo "# 6/6  run_zkvm.sh (GPU only; CPU passes take days)"
echo "########################################"
ZKVM_PASSES=cuda "$SCRIPT_DIR/run_zkvm.sh" || echo "  !! run_zkvm.sh failed (continuing)"

echo ""
echo "=== run_all.sh complete ==="
