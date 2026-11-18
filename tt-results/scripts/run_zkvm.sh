#!/usr/bin/env bash
# Run the SP1 zkVM baseline (third-party-bench/zkvm) on the suites of
# ZKVM_SUITES (default "tpch"; "micro" is run_micro.sh's), in the proof modes of
# ZKVM_MODES (default "compressed,groth16").
#
# It uses the GPU prover (sp1-gpu-server, downloaded on first use). The server
# is linked against the CUDA 12 runtime; on a CUDA 13 machine put
# libcudart.so.12 (from NVIDIA's nvidia-cuda-runtime-cu12 wheel) in
# ZKVM_CUDA12_LIB (default ~/.sp1/lib/cuda12).
# ZKVM_SFS (default 0.01,0.02,0.04,0.05,0.1) and ZKVM_QUERIES narrow the
# TPC-H sweep; MICRO_POWS and MICRO_QUERIES the micro one. It needs the baseline's tables and the DataFusion results it is
# checked against:
#   (cd third-party-bench && cargo run --release --bin tpch_reference -- <sf>...)
#
# Outputs to tt-results/raw/: zkvm_<suite>_cuda.{log,json}, read by
# parse_zkvm_tpch.py (tpch) and parse_micro.py (micro).
#
# Usage:
#   ./tt-results/scripts/run_zkvm.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
ZKVM_DIR="$REPO_ROOT/third-party-bench/zkvm"
PARSER="$REPO_ROOT/third-party-bench/parse_bench_output.py"

export PATH="$PATH:$HOME/.sp1/bin"
CUDA12_LIB="${ZKVM_CUDA12_LIB:-$HOME/.sp1/lib/cuda12}"
mkdir -p "$RESULTS_DIR"

(cd "$ZKVM_DIR" && cargo build --release -p tt-zkvm-script --features cuda 2>&1) || exit 1

for suite in ${ZKVM_SUITES:-tpch}; do
    log="$RESULTS_DIR/zkvm_${suite}_cuda.log"
    echo ""
    echo "=============================================="
    echo "  SP1 zkVM $suite bench (GPU)"
    echo "=============================================="
    # The log is resumed: runs it already has are skipped. A run whose process
    # is killed gets a `failed` line and the bench restarts after it. Delete
    # the log to start over.
    while true; do
        (cd "$ZKVM_DIR" && ZKVM_RESUME_LOG="$log" SP1_PROVER=cuda \
            LD_LIBRARY_PATH="$CUDA12_LIB:${LD_LIBRARY_PATH:-}" "./target/release/$suite" 2>&1) \
            | tee -a "$log"
        status=${PIPESTATUS[0]}
        [[ $status == 0 ]] && break
        last=$(grep -E '^(start|query|failed) ' "$log" | tail -1)
        if [[ $last != start* ]]; then
            echo "  !! zkvm $suite exited with $status outside a proof; giving up" | tee -a "$log"
            break
        fi
        echo "failed ${last#start } exit=$status" | tee -a "$log"
    done
    python3 "$PARSER" zkvm "$log" "$RESULTS_DIR/zkvm_${suite}_cuda.json" \
        || echo "  !! parser failed for zkvm $suite"
done

echo ""
echo "=== zkVM sweep complete ==="
