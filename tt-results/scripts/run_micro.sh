#!/usr/bin/env bash
# Run the three micro-benchmark suites (PoSQL, QEDB, TruthTable) on the
# shared Filter / Aggregate / Limit / Join / Join_PK_FK queries, and emit
# both raw stdout logs and structured per-bench JSON files.
#
# Outputs to tt-results/raw/:
#   third_party_{bench}.log   — full cargo bench stdout (one per system)
#   third_party_{bench}.json  — parsed/structured results (one per system)
#
# The per-bench JSONs are what parse_micro.py consumes; the logs are kept for
# debugging.
#
# Thread pinning: NUM_THREADS (default 1) is propagated as RAYON_NUM_THREADS
# (consumed by Rayon) AND TT_BENCH_NUM_THREADS (stamped into the JSON output
# by parse_bench_output.py). The two MUST match — otherwise micro.csv lies
# about what was measured.
#
# Failures in one bench don't abort the others.
#
# Usage:
#   ./tt-results/scripts/run_micro.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
TPB_DIR="$REPO_ROOT/third-party-bench"
PARSER="$TPB_DIR/parse_bench_output.py"

mkdir -p "$RESULTS_DIR"

# Note: truth_table is now run TWICE, once per SNARK backend, via
# run_bench_variant below. Keep this list for the "single-shot" benches only.
BENCHES=(sxt_proof_of_sql qedb)
NUM_THREADS=1       # threads for the measured pass
WARMUP_THREADS=16   # threads for the unmeasured QEDB warmup (see below)

# QEDB regenerates its setup keys / cache on first contact with a fresh
# artifact/size_N directory. That work parallelizes well but is single-
# threaded slow, so we run QEDB ONCE at WARMUP_THREADS just to populate
# `artifact/size_N/qedb_cache/` and discard the timing log. The measured
# pass then runs everything (incl. QEDB again) at NUM_THREADS=1 with the
# cache already warm, so only the prover work is measured single-threaded.
#
# This is idempotent: if qedb_cache/ already exists from a previous invocation
# the warmup is mostly a no-op (QEDB skips work it already has).

# Join + Join_PK_FK parquets share a deterministic PK/FK row layout written
# by sxt's bench and read by the other two. Wipe stale ones so downstream
# benches don't read mismatched data. Filter / Aggregate / Limit parquets
# are independent and reused.
ARTIFACT_ROOT="$TPB_DIR/artifact"
if [[ -d "$ARTIFACT_ROOT" ]]; then
    find "$ARTIFACT_ROOT" -type d \( -name Join -o -name Join_PK_FK \) -prune -print0 \
        | xargs -0 -I {} rm -rf {}
fi

warmup_qedb() {
    local log="$RESULTS_DIR/third_party_qedb_warmup.log"

    echo ""
    echo "=============================================="
    echo "  WARMUP: cargo bench --bench qedb  (threads=$WARMUP_THREADS, discarded)"
    echo "=============================================="

    (
        cd "$TPB_DIR"
        RAYON_NUM_THREADS="$WARMUP_THREADS" \
            cargo bench --bench qedb 2>&1
    ) | tee "$log"

    echo ""
    echo "  → warmup log (not parsed): $log"
}

run_bench() {
    local bench="$1"
    local log="$RESULTS_DIR/third_party_${bench}.log"

    echo ""
    echo "=============================================="
    echo "  cargo bench --bench $bench  (threads=$NUM_THREADS)"
    echo "=============================================="

    (
        cd "$TPB_DIR"
        RAYON_NUM_THREADS="$NUM_THREADS" \
            cargo bench --bench "$bench" 2>&1
    ) | tee "$log"

    echo ""
    echo "  → log: $log"

    TT_BENCH_NUM_THREADS="$NUM_THREADS" \
        python3 "$PARSER" "$bench" "$log" "$RESULTS_DIR/third_party_${bench}.json" \
        || echo "  !! parser failed for $bench"
}

# Variant of run_bench that activates a cargo feature and tags the output
# files with a suffix, so the same bench can be run with different SNARK
# backends (BN254 vs BLS12-381) without overwriting each other. Empty
# `feature` means "default features" (BN254 for truth_table).
run_bench_variant() {
    local bench="$1"
    local suffix="$2"   # "" for default, e.g. "_bls12_381" for BLS variant
    local feature="$3"  # "" for default, e.g. "bls12-381" for BLS variant

    local log="$RESULTS_DIR/third_party_${bench}${suffix}.log"
    local feature_args=()
    if [[ -n "$feature" ]]; then
        feature_args=(--features "$feature")
    fi

    echo ""
    echo "=============================================="
    echo "  cargo bench --bench $bench ${feature_args[*]:-(default features)}  (threads=$NUM_THREADS)"
    echo "=============================================="

    (
        cd "$TPB_DIR"
        RAYON_NUM_THREADS="$NUM_THREADS" \
            cargo bench --bench "$bench" "${feature_args[@]}" 2>&1
    ) | tee "$log"

    echo ""
    echo "  → log: $log"

    TT_BENCH_NUM_THREADS="$NUM_THREADS" \
        python3 "$PARSER" "$bench" "$log" "$RESULTS_DIR/third_party_${bench}${suffix}.json" \
        || echo "  !! parser failed for $bench${suffix}"
}

echo "=== micro comparison sweep ==="
echo "Benches: ${BENCHES[*]}"
echo "Warmup threads: $WARMUP_THREADS (QEDB only, output discarded)"
echo "Measured threads: $NUM_THREADS"
echo "Results dir: $RESULTS_DIR"

warmup_qedb

for b in "${BENCHES[@]}"; do
    run_bench "$b"
done

# TruthTable: one pass per SNARK backend. BN254 is the default; the
# `bls12-381` feature swaps the type alias in tt-exec. Each pass writes to a
# distinct JSON so parse_micro.py can carry both into the same micro.csv.
run_bench_variant truth_table ""             ""
run_bench_variant truth_table "_bls12_381"   "bls12-381"

echo ""
echo "=== micro sweep complete ==="
echo "Logs:  $RESULTS_DIR/third_party_*.log"
echo "JSONs: $RESULTS_DIR/third_party_*.json"
