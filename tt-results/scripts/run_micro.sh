#!/usr/bin/env bash
# Run the micro benchmark (third-party-bench/src/micro.rs) on every system, all
# over the same rows: TruthTable, PoSQL, QEDB and Poneglyph on one CPU thread,
# the no-proof baseline on 1 and 4 threads, and the SP1 zkVM on the GPU. All
# proof systems use BN254 (QEDB through its fork's `bn254` feature).
#
# Provers run once; verifiers repeat for up to a second and report the median.
# Each system also reports what it has of: setup time, proving and verifying
# key sizes, KZG parameter size and key generation (Poneglyph), table
# commitment time and size, proof size and result rows.
#
# MICRO_SYSTEMS picks systems (default "tt posql qedb poneglyph baseline zkvm");
# MICRO_POWS (comma-separated powers of two, default 15..20) and MICRO_QUERIES
# narrow the sweep. PoSQL uses its arkworks MSMs (third-party-bench's
# posql-blitzar feature is off). CPU systems are pinned to CPUs 0..t-1, distinct physical
# cores on the bench machine (check `lscpu -e` elsewhere), and see no GPU:
# only the zkVM proves on the GPU.
#
# Outputs to tt-results/raw/:
#   third_party_{truth_table,sxt_proof_of_sql,qedb,poneglyph}.{log,json}
#   third_party_baseline_{1,4}.{log,json}
#   zkvm_micro_cuda.{log,json}
# then, from the repo root:
#   python3 tt-results/scripts/parse_micro.py   # → tidy/micro.csv
#   python3 tt-results/scripts/plot_micro.py    # → figures/micro*.pdf
#
# Usage:
#   ./tt-results/scripts/run_micro.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
TPB_DIR="$REPO_ROOT/third-party-bench"
PARSER="$TPB_DIR/parse_bench_output.py"
SYSTEMS=(${MICRO_SYSTEMS:-tt posql qedb poneglyph baseline zkvm})
mkdir -p "$RESULTS_DIR"

has() {
    [[ " ${SYSTEMS[*]} " == *" $1 "* ]]
}

# Build before any timed run, and write every table's parquet file so the
# zkVM reads the rows the other systems generate.
(
    cd "$TPB_DIR"
    cargo bench --no-run --bench truth_table --bench sxt_proof_of_sql --bench qedb \
        --bench poneglyph --bench baseline 2>&1 | tail -2
    cargo run --release --bin micro_data >/dev/null
) || exit 1

# run_bench <bench> <threads> <output stem> [cargo args...]
run_bench() {
    local bench="$1" threads="$2" stem="$3"
    shift 3
    local log="$RESULTS_DIR/${stem}.log"
    echo ""
    echo "=============================================="
    echo "  $bench (threads=$threads, CPUs 0-$((threads - 1)))"
    echo "=============================================="
    (
        cd "$TPB_DIR"
        CUDA_VISIBLE_DEVICES="" RAYON_NUM_THREADS="$threads" taskset -c "0-$((threads - 1))" \
            cargo bench "$@" --bench "$bench" 2>&1
    ) | tee "$log"
    TT_BENCH_NUM_THREADS="$threads" \
        python3 "$PARSER" "$bench" "$log" "$RESULTS_DIR/${stem}.json" \
        || echo "  !! parser failed for $bench"
}

has tt && run_bench truth_table 1 third_party_truth_table
has posql && run_bench sxt_proof_of_sql 1 third_party_sxt_proof_of_sql
has qedb && run_bench qedb 1 third_party_qedb
has poneglyph && run_bench poneglyph 1 third_party_poneglyph
if has baseline; then
    run_bench baseline 1 third_party_baseline_1
    run_bench baseline 4 third_party_baseline_4
fi
if has zkvm; then
    rm -f "$RESULTS_DIR/zkvm_micro_cuda.log"
    ZKVM_SUITES=micro "$SCRIPT_DIR/run_zkvm.sh"
fi

echo ""
echo "=== micro sweep complete ==="
