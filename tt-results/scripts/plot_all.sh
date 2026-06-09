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
echo "# 1/5  plot_tt_tpch.py           → tpch_tt_*.pdf"
echo "########################################"
python3 "$SCRIPT_DIR/plot_tt_tpch.py" || echo "  !! plot_tt_tpch.py failed (continuing)"

echo ""
echo "########################################"
echo "# 2/5  plot_pgn.py               → tpch_pgn_*.pdf"
echo "########################################"
python3 "$SCRIPT_DIR/plot_pgn.py" || echo "  !! plot_pgn.py failed (continuing)"

echo ""
echo "########################################"
echo "# 3/5  plot_micro.py             → micro_*.pdf"
echo "########################################"
python3 "$SCRIPT_DIR/plot_micro.py" || echo "  !! plot_micro.py failed (continuing)"

echo ""
echo "########################################"
echo "# 4/5  plot_commit.py            → commit_time.pdf"
echo "########################################"
python3 "$SCRIPT_DIR/plot_commit.py" || echo "  !! plot_commit.py failed (continuing)"

echo ""
echo "########################################"
echo "# 5/5  plot_tt_tpch_combined.py  → tpch_tt_combined.pdf"
echo "########################################"
python3 "$SCRIPT_DIR/plot_tt_tpch_combined.py" || echo "  !! plot_tt_tpch_combined.py failed (continuing)"

echo ""
echo "=== plot_all.sh complete ==="
# Note: tpch_optall produces CSV only (no plot) — its purpose is to isolate
# per-rule contributions, which can be read directly from the CSV. The
# combined "all_on" baseline lives in plot_tt_tpch.py's outputs.
