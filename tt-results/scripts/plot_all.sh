#!/usr/bin/env bash
# Render every figure under tt-results/figures/.
#
# Failures in one plot don't abort the others.
#
# Usage:
#   ./tt-results/scripts/plot_all.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "########################################"
echo "# 1/3  plot_tt_tpch.py  → tpch_tt_*.pdf"
echo "########################################"
python3 "$SCRIPT_DIR/plot_tt_tpch.py" || echo "  !! plot_tt_tpch.py failed (continuing)"

echo ""
echo "########################################"
echo "# 2/3  plot_pgn.py      → tpch_pgn_*.pdf"
echo "########################################"
python3 "$SCRIPT_DIR/plot_pgn.py" || echo "  !! plot_pgn.py failed (continuing)"

echo ""
echo "########################################"
echo "# 3/3  plot_micro.py    → micro_*.pdf"
echo "########################################"
python3 "$SCRIPT_DIR/plot_micro.py" || echo "  !! plot_micro.py failed (continuing)"

echo ""
echo "=== plot_all.sh complete ==="
