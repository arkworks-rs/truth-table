# TPC-H Benchmarks

This directory contains the TPC-H benchmark harness for `exec/benches`.

## Run all TPC-H benches

```
cargo bench -p exec --bench benches -- tpch
```

## Run a single TPC-H case (prover or verifier)

Divan filters are path-based. In this setup, the full path is:

```
tpch::bench_tpch_prover::tpch_q18
tpch::bench_tpch_verifier::tpch_q18
```

Recommended commands:

```
# Verifier only
cargo bench -p exec --bench benches -- tpch::bench_tpch_verifier::tpch_q18 --skip bench_tpch_prover

# Prover only
cargo bench -p exec --bench benches -- tpch::bench_tpch_prover::tpch_q18 --skip bench_tpch_verifier
```

## List available benches

```
cargo bench -p exec --bench benches -- --list
```
