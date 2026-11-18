#!/usr/bin/env bash
# Run the SP1 zkVM baseline (third-party-bench/zkvm) on the micro queries and
# the TPC-H ones (ZKVM_SUITES, default "micro tpch"), each in the proof modes
# of ZKVM_MODES (default "compressed,groth16").
#
# Passes (ZKVM_PASSES, default "cpu:1 cpu:4 cuda"):
#   cpu:<t>  the CPU prover on t threads, pinned to CPUs 0..t-1 (distinct
#            physical cores on the bench machine; check `lscpu -e` elsewhere).
#            SP1 proves 4 core shards and 8 recursion shards at once by
#            default, which needs over 100 GB; on t <= 4 cores that buys
#            nothing, so CPU passes prove one shard of each kind at a time.
#   cuda     the GPU prover (sp1-gpu-server, downloaded on first use). The
#            server is linked against the CUDA 12 runtime; on a CUDA 13
#            machine put libcudart.so.12 (from NVIDIA's
#            nvidia-cuda-runtime-cu12 wheel) in ZKVM_CUDA12_LIB (default
#            ~/.sp1/lib/cuda12).
# ZKVM_POWS (micro, default 16,17,18,19), ZKVM_SFS (TPC-H, default
# 0.01,0.02,0.04,0.05,0.1) and ZKVM_QUERIES narrow the sweep. TPC-H needs the
# baseline's tables and the DataFusion results it is checked against:
#   (cd third-party-bench && cargo run --release --bin tpch_reference -- <sf>...)
#
# Outputs to tt-results/raw/:
#   third_party_zkvm_<pass>.{log,json} — micro (<pass> = cpu1, cpu4, cuda),
#                                         read by parse_micro.py
#   zkvm_tpch_<pass>.{log,json}         — TPC-H, read by parse_zkvm_tpch.py
#
# Usage:
#   ./tt-results/scripts/run_zkvm.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$REPO_ROOT/tt-results/raw"
ZKVM_DIR="$REPO_ROOT/third-party-bench/zkvm"
PARSER="$REPO_ROOT/third-party-bench/parse_bench_output.py"
PASSES=(${ZKVM_PASSES:-cpu:1 cpu:4 cuda})
SUITES=(${ZKVM_SUITES:-micro tpch})

export PATH="$PATH:$HOME/.sp1/bin"
CUDA12_LIB="${ZKVM_CUDA12_LIB:-$HOME/.sp1/lib/cuda12}"
mkdir -p "$RESULTS_DIR"

# One build serves both provers; SP1_PROVER picks one at run time.
(cd "$ZKVM_DIR" && cargo build --release -p tt-zkvm-script --features cuda 2>&1) || exit 1

for pass in "${PASSES[@]}"; do
    prover="${pass%%:*}"
    if [[ "$prover" == "cuda" ]]; then
        tag="cuda"
        run=(env SP1_PROVER=cuda LD_LIBRARY_PATH="$CUDA12_LIB:${LD_LIBRARY_PATH:-}")
    else
        threads="${pass#*:}"
        tag="cpu${threads}"
        run=(env SP1_PROVER=cpu RAYON_NUM_THREADS="$threads"
            SP1_WORKER_NUM_CORE_WORKERS=1 SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=1
            taskset -c "0-$((threads - 1))")
    fi
    for suite in "${SUITES[@]}"; do
        if [[ "$suite" == "micro" ]]; then
            stem="third_party_zkvm_${tag}"
        else
            stem="zkvm_tpch_${tag}"
        fi
        log="$RESULTS_DIR/${stem}.log"
        echo ""
        echo "=============================================="
        echo "  SP1 zkVM $suite bench ($pass)"
        echo "=============================================="
        (cd "$ZKVM_DIR" && "${run[@]}" "./target/release/$suite" 2>&1) | tee "$log"
        TT_BENCH_NUM_THREADS="${threads:-}" \
            python3 "$PARSER" zkvm "$log" "$RESULTS_DIR/${stem}.json" \
            || echo "  !! parser failed for zkvm $suite ($pass)"
    done
    unset threads
done

echo ""
echo "=== zkVM sweep complete ==="
