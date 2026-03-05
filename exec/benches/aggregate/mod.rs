use std::sync::OnceLock;

use divan::Bencher;

use crate::support::{
    BenchCase, build_verifier_state, emit_benchmark_stats_row, ensure_proof, fork_arg_verifier,
    load_proof_bytes_cached, log_proof_size_once, prepare_assets_cached, prepare_prover_iteration,
    run_arg_verifier_once, run_prover_iteration, warmup_proof,
};

fn aggregate_cases() -> &'static [BenchCase] {
    // Static list of aggregation queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases = vec![
            BenchCase {
                name: "aggr_count",
                query: r#"SELECT l_suppkey, COUNT(l_suppkey) FROM lineitem GROUP BY l_suppkey,l_orderkey"#,
                tables: &["lineitem"],
            },
            BenchCase {
                name: "aggr_sum",
                query: r#"SELECT l_suppkey, SUM(l_suppkey) FROM lineitem GROUP BY l_suppkey,l_orderkey"#,
                tables: &["lineitem"],
            },
            BenchCase {
                name: "aggr_max",
                query: r#"SELECT l_suppkey, MAX(l_suppkey) FROM lineitem GROUP BY l_suppkey,l_orderkey"#,
                tables: &["lineitem"],
            },
            BenchCase {
                name: "aggr_min",
                query: r#"SELECT l_suppkey, MIN(l_suppkey) FROM lineitem GROUP BY l_suppkey,l_orderkey"#,
                tables: &["lineitem"],
            },
            BenchCase {
                name: "full_aggr_count",
                query: r#"SELECT COUNT(*) FROM lineitem"#,
                tables: &["lineitem"],
            },
            BenchCase {
                name: "full_aggr_sum",
                query: r#"SELECT SUM(l_suppkey) FROM lineitem"#,
                tables: &["lineitem"],
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = aggregate_cases(), max_time = 1)]
fn bench_aggregate_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    let assets = prepare_assets_cached(case);
    bencher
        .with_inputs(|| prepare_prover_iteration(&assets))
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
    emit_benchmark_stats_row("bench_aggregate_prover", case.name);
}

#[divan::bench(args = aggregate_cases(), max_time = 1)]
fn bench_aggregate_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: build state once, then time only run_verifier_once.
    let assets = prepare_assets_cached(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    let proof_bytes = load_proof_bytes_cached(case.name, &bench_proof);
    let state = build_verifier_state(&assets, proof_bytes.as_slice());
    bencher
        .with_inputs(|| fork_arg_verifier(&state))
        .bench_local_values(run_arg_verifier_once);
    emit_benchmark_stats_row("bench_aggregate_verifier", case.name);
}
