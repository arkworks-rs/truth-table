#!/usr/bin/env bash
# Run-and-dump every benchmark suite: TT TPC-H, Poneglyph comparison, micro.
#
# Failures in one suite don't abort the others.
#
# Usage:
#   ./tt-results/scripts/run_all.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "########################################"
echo "# 1/3  run_tt_tpch.sh"
echo "########################################"
"$SCRIPT_DIR/run_tt_tpch.sh" || echo "  !! run_tt_tpch.sh failed (continuing)"

echo ""
echo "########################################"
echo "# 2/3  run_pgn.sh"
echo "########################################"
"$SCRIPT_DIR/run_pgn.sh" || echo "  !! run_pgn.sh failed (continuing)"

echo ""
echo "########################################"
echo "# 3/3  run_micro.sh"
echo "########################################"
"$SCRIPT_DIR/run_micro.sh" || echo "  !! run_micro.sh failed (continuing)"

echo ""
echo "=== run_all.sh complete ==="
