#!/usr/bin/env bash
# One-shot campaign to refresh every TruthTable number that feeds the paper:
#   1. TT TPC-H (_tt, all 17 queries)  at SF {0.05, 0.1} x threads {4, 1}
#   2. TT-on-pgn (6 _pgn variants)     at SF {0.01, 0.02, 0.04} x 1 thread
#      (PoneglyphDB itself is NOT rerun: PGN_SKIP_PONEGLYPH=1)
#   3. Micro suite, TruthTable only (BN254 + BLS12-381): MICRO_ONLY_TT=1
# then rebuilds the three tidy CSVs and re-renders every figure.
#
# Designed to run detached (setsid) so it survives terminal/laptop closes.
#
# Usage:
#   setsid nohup ./tt-results/scripts/campaign_paper_update.sh \
#       > tt-results/raw/campaign_paper_update.log 2>&1 &

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV_PY="$REPO_ROOT/tt-results/.venv/bin/python"
cd "$REPO_ROOT"

stage() {
    echo ""
    echo "############################################################"
    echo "# $1   ($(date '+%F %T'))"
    echo "############################################################"
}

stage "1/3 run_tt_tpch.sh — 17 _tt queries, SF {0.05,0.1} x {4,1} threads"
"$SCRIPT_DIR/run_tt_tpch.sh" || echo "  !! run_tt_tpch.sh failed (continuing)"

stage "2/3 run_pgn.sh (TT side only) — 6 _pgn queries, SF {0.01,0.02,0.04} x 1 thread"
PGN_SKIP_PONEGLYPH=1 "$SCRIPT_DIR/run_pgn.sh" || echo "  !! run_pgn.sh failed (continuing)"

stage "3/3 run_micro.sh (TT only, both backends)"
MICRO_ONLY_TT=1 "$SCRIPT_DIR/run_micro.sh" || echo "  !! run_micro.sh failed (continuing)"

stage "parse — rebuild tidy CSVs"
"$VENV_PY" "$SCRIPT_DIR/parse_tt_tpch.py" || echo "  !! parse_tt_tpch failed"
"$VENV_PY" "$SCRIPT_DIR/parse_pgn.py"     || echo "  !! parse_pgn failed"
"$VENV_PY" "$SCRIPT_DIR/parse_micro.py"   || echo "  !! parse_micro failed"

stage "plot — re-render figures"
"$VENV_PY" "$SCRIPT_DIR/plot_tt_tpch.py" || echo "  !! plot_tt_tpch failed"
"$VENV_PY" "$SCRIPT_DIR/plot_pgn.py"     || echo "  !! plot_pgn failed"
"$VENV_PY" "$SCRIPT_DIR/plot_micro.py"   || echo "  !! plot_micro failed"

stage "campaign complete"
echo "CSVs:    $REPO_ROOT/tt-results/tidy/"
echo "Figures: $REPO_ROOT/tt-results/figures/"
