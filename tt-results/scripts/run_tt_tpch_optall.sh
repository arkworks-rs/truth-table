#!/usr/bin/env bash
# Run the bundled optimization-rule sweep: 17 TPC-H _tt queries × 3 configs
# (all_off / pkfk_on_remat_off / pkfk_off_remat_on) at SF=0.05, threads=1.
#
# The `all_on` config (both rules enabled — production defaults) is intentionally
# omitted here; the baseline `run_tt_tpch.sh` sweep already covers it.
#
# Bench naming convention (see crates/tt-exec/benches/tpch_optall/mod.rs):
#   tpch_q{N}_tt_{all_off|pkfk_on_remat_off|pkfk_off_remat_on}
#
# Errors in any single (query, config) cell are logged but never abort the
# sweep. The proof cache is wiped once at the start since each config
# produces a structurally-different proof for the same query.
#
# Output files (renamed from the shared bench output paths):
#   benches_tt_optall_0.05_1.json
#   bench_stats_tt_optall_0.05_1.jsonl
#   tpch_tt_optall_0.05_1_{query_case}.txt
#
# Usage:
#   ./tt-results/scripts/run_tt_tpch_optall.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
mkdir -p "$RESULTS_DIR"

# SF=0.05 (not 0.1): Q9 all_off pins every join to MANY_TO_MANY and disables
# rematerialize, and at SF=0.1 the match-pair blowup OOM-kills the prover on a
# 128GB box with no swap. SF=0.05 stays under the memory ceiling, and the
# baseline tpch.csv already has SF=0.05 rows to compare against.
SF="0.05"
THREADS="1"
TAG="${SF}_${THREADS}"

QUERY_NUMS=(1 2 3 4 5 6 7 8 9 10 12 14 15 17 18 19 20)
CONFIGS=(all_off pkfk_on_remat_off pkfk_off_remat_on)

BENCHES_JSON="$RESULTS_DIR/benches.json"
BENCH_STATS_JSONL="$RESULTS_DIR/bench_stats.jsonl"

echo "=== TT TPC-H bundled optimization (all_on / all_off) sweep ==="
echo "Queries:    ${#QUERY_NUMS[@]}"
echo "Configs:    ${#CONFIGS[@]}  (${CONFIGS[*]})"
echo "Total cases: $(( ${#QUERY_NUMS[@]} * ${#CONFIGS[@]} ))"
echo "Scale factor: $SF   Threads: $THREADS"
echo "Results dir: $RESULTS_DIR"

# Each (query, config) cell produces a structurally distinct proof; the cache
# is keyed by case name so different configs don't collide, but we wipe once
# at the start to guarantee a clean slate for this run.
proof_cache="$REPO_ROOT/artifacts/bench-proof-cache"
[[ -d "$proof_cache" ]] && rm -rf "$proof_cache"

# Always re-generate at $SF — the existence check is unsafe because other
# benches (run_pgn.sh, etc.) may have overwritten bench-data with a different
# scale factor. Running optall on the wrong SF produces apparently-fine numbers
# that silently disagree with the matching-SF baseline.
bench_data="$REPO_ROOT/artifacts/bench-data"
echo ""
echo "=============================================="
echo "  data-gen --scale $SF (forced)"
echo "=============================================="
cargo run -p tt-exec --bin tt -- data-gen --scale "$SF" --output-dir "$bench_data" || true

rm -f "$BENCHES_JSON" "$BENCH_STATS_JSONL"

for q in "${QUERY_NUMS[@]}"; do
    for cfg in "${CONFIGS[@]}"; do
        case_name="tpch_q${q}_tt_${cfg}"
        # divan registers each variant as `tpch_optall::q{N}_{cfg}::{prover|verifier_*}`,
        # so filter on the module path (not on `case_name`, which is only used as
        # the proof-cache / stats-row label).
        divan_path="tpch_optall::q${q}_${cfg}"
        logfile="$RESULTS_DIR/tpch_tt_optall_${TAG}_${case_name}.txt"
        echo ""
        echo ">>> [SF=$SF, ${THREADS}t] $case_name"
        RAYON_NUM_THREADS="$THREADS" \
            cargo bench -p tt-exec --bench benches -- "${divan_path}::" \
            2>&1 | tee "$logfile" \
            || echo "  !! $case_name failed (continuing)"
    done
done

[[ -f "$BENCHES_JSON" ]]      && mv "$BENCHES_JSON"      "$RESULTS_DIR/benches_tt_optall_${TAG}.json"
[[ -f "$BENCH_STATS_JSONL" ]] && mv "$BENCH_STATS_JSONL" "$RESULTS_DIR/bench_stats_tt_optall_${TAG}.jsonl"

echo ""
echo "  → saved benches_tt_optall_${TAG}.json, bench_stats_tt_optall_${TAG}.jsonl"
echo ""
echo "=== TT TPC-H optall sweep complete ==="
