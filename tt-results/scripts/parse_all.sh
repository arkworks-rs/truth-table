#!/usr/bin/env bash
# Rebuild all tidy CSVs from the raw outputs in tt-results/raw/.
#
# Each parser owns its own CSV; missing raw files are tolerated (the parser
# logs and continues). Failures in one parser don't abort the others.
#
# Usage:
#   ./tt-results/scripts/parse_all.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "########################################"
echo "# 1/4  parse_tt_tpch.py            → tidy/tpch.csv"
echo "########################################"
python3 "$SCRIPT_DIR/parse_tt_tpch.py" || echo "  !! parse_tt_tpch.py failed (continuing)"

echo ""
echo "########################################"
echo "# 2/4  parse_pgn.py                → tidy/tpch_pgn.csv"
echo "########################################"
python3 "$SCRIPT_DIR/parse_pgn.py" || echo "  !! parse_pgn.py failed (continuing)"

echo ""
echo "########################################"
echo "# 3/4  parse_micro.py              → tidy/micro.csv"
echo "########################################"
python3 "$SCRIPT_DIR/parse_micro.py" || echo "  !! parse_micro.py failed (continuing)"

echo ""
echo "########################################"
echo "# 4/4  parse_tt_tpch_optall.py     → tidy/tpch_optall.csv"
echo "########################################"
python3 "$SCRIPT_DIR/parse_tt_tpch_optall.py" || echo "  !! parse_tt_tpch_optall.py failed (continuing)"

echo ""
echo "=== parse_all.sh complete ==="
