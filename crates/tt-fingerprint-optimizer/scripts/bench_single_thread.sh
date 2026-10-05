#!/bin/bash
# Single-threaded fingerprint benchmark, no cost model: every number is a
# measured run (pinned to core 0, RAYON_NUM_THREADS=1). Resumable: rows
# already in the CSVs are skipped. Run from anywhere; the output directory
# ($1, default artifacts/fp-bench-1t) must hold queries.csv
# (regime,chain,natural,pattern: regime 0/1/2 = <1% / 1–25% / 25–50% of rows
# matched; chain and natural from tt-fp-calibrate --shape-only, as
# results/bench-queries-l_comment.csv).
# Plot with scripts/plot_bench.py.
#   commits.csv : bins,run,commit_s,oracle_bytes,bins_bytes
#   proofs.csv  : kind,width,k,regime,pattern,prove_s,verify_s,proof_bytes,result_rows
#   survivors.csv : pattern,k,rows,survivors,matches (needs tt-fp-calibrate,
#                   built with --features calibration)
# kind: baseline (no fingerprints), forced (width 2048, first k greedy bins),
#       natural (prover's own choice at a committed width).
set -u
cd "$(dirname "$0")/../../.."
D=$(realpath "${1:-artifacts/fp-bench-1t}")
PQ=artifacts/bench-data/lineitem.parquet; PK=artifacts/tt_pk_25_bn254.pk; VK=artifacts/tt_vk_25_bn254.vk
M=./target/release/tt-fp-measure
ONE="env RAYON_NUM_THREADS=1 taskset -c 0"
C=$D/commits.csv; P=$D/proofs.csv
[ -f $C ] || echo "bins,run,commit_s,oracle_bytes,bins_bytes" > $C
[ -f $P ] || echo "kind,width,k,regime,pattern,prove_s,verify_s,proof_bytes,result_rows" > $P
mkdir -p $D/oracles $D/proof

# 1. Commits: every width, 3 runs; run 1's oracle is kept for proving.
for run in 1 2 3; do for b in 0 16 64 128 256 512 1024 2048; do
  grep -q "^$b,$run," $C && continue
  out=$($ONE $M commit --parquet $PQ --pk $PK --bins $b --out $D/oracles/w$b-r$run.oracle 2>>$D/err.log) || { echo "commit $b $run failed" >> $D/err.log; continue; }
  echo "$b,$run,${out#*,}" >> $C
  [ $run -gt 1 ] && rm -f $D/oracles/w$b-r$run.oracle $D/oracles/w$b-r$run.oracle.bins
done; done

prove() { # kind width k regime pattern oracle [forced k]
  local kind=$1 width=$2 k=$3 regime=$4 pattern=$5 oracle=$6 force=${7:-}
  grep -qF "$kind,$width,$k,$regime,$pattern," $P && return
  if [ -n "$force" ]; then
    out=$(TT_PREFILTER_FORCE_BINS=$force $ONE $M query --parquet $PQ --oracle $oracle --pk $PK --vk $VK --pattern "$pattern" --out-dir $D/proof 2>>$D/err.log)
  else
    out=$($ONE $M query --parquet $PQ --oracle $oracle --pk $PK --vk $VK --pattern "$pattern" --out-dir $D/proof 2>>$D/err.log)
  fi
  if [ -n "$out" ]; then echo "$kind,$width,$k,$regime,$out" >> $P; else echo "prove $kind $width $k $pattern failed" >> $D/err.log; fi
}
queries() { tail -n +2 $D/queries.csv; }

# 2. Baselines: no fingerprints committed, so no pre-filter.
queries | while IFS=, read -r regime chain natural pattern; do
  prove baseline 0 0 $regime "$pattern" $D/oracles/w0-r1.oracle
done
# 3. Forced k at 2048 bins, k up to 8; a chain shorter than 8 also gets its
#    full length measured, and k past the chain is the full chain (not
#    re-run).
for k in 1 2 3 4 5 6 7 8; do
  queries | while IFS=, read -r regime chain natural pattern; do
    case " 1 2 3 4 6 8 " in *" $k "*) ;; *) [ $k -eq $chain ] || continue ;; esac
    [ $k -gt $chain ] && continue
    prove forced 2048 $k $regime "$pattern" $D/oracles/w2048-r1.oracle $k
  done
done
# 4. The prover's own choice at each committed width (2048 is the forced
#    run at its natural k, the same proof).
for w in 16 64 128 256 512 1024; do
  queries | while IFS=, read -r regime chain natural pattern; do
    prove natural $w - $regime "$pattern" $D/oracles/w$w-r1.oracle
  done
done
# 5. Rows surviving the first k bins of each chain: exact counts from the
#    same greedy on the data, no proof (tt-fp-calibrate --shape-only).
S=$D/survivors.csv
[ -f $S ] || echo "pattern,k,rows,survivors,matches" > $S
queries | while IFS=, read -r regime chain natural pattern; do
  for k in 1 2 3 4 6 8; do
    [ $k -gt $chain ] && k=$chain
    grep -qF "$pattern,$k," $S && continue
    TT_PREFILTER_FORCE_BINS=$k ./target/release/tt-fp-calibrate --pattern "$pattern" --shape-only 2>/dev/null \
      | awk -F, -v p="$pattern" '{print p","$2","$3","$5","$7}' >> $S
  done
done
echo ALL-DONE >> $D/run.log
