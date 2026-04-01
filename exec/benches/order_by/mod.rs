use std::sync::OnceLock;

use divan::Bencher;

use crate::support::{
    BenchCase, build_verifier_full_state_from_proof, emit_benchmark_stats_row, ensure_proof,
    log_proof_size_once, prepare_assets_cached, prepare_prover_iteration, run_full_verifier_once,
    run_preprocess_once, run_prover_iteration, warmup_proof,
};

fn order_by_cases() -> &'static [BenchCase] {
    // Static list of ORDER BY queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases = vec![
            BenchCase {
                name: "order_by_single_col",
                query: r#"SELECT l_suppkey FROM lineitem ORDER BY l_suppkey LIMIT 128"#,
                tables: &["lineitem"],
            },
            BenchCase {
                name: "order_by_multi_col",
                query: r#"SELECT l_partkey, l_suppkey FROM lineitem WHERE l_partkey < 1000 ORDER BY l_partkey, l_suppkey LIMIT 256"#,
                tables: &["lineitem"],
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = order_by_cases(), max_time = 1)]
fn bench_order_by_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    let assets = prepare_assets_cached(case);
    bencher
        .with_inputs(|| prepare_prover_iteration(&assets))
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
    emit_benchmark_stats_row("bench_order_by_prover", case.name);
}

#[divan::bench(args = order_by_cases(), sample_size = 10)]
fn bench_order_by_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: preprocess once, then time from tracking onward.
    let assets = prepare_assets_cached(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, case.query, &bench_proof);
    let state = build_verifier_full_state_from_proof(&assets, &bench_proof.proof);
    run_preprocess_once(&state);
    bencher.bench_local(|| {
        run_full_verifier_once(&state);
    });
    emit_benchmark_stats_row("bench_order_by_verifier", case.name);
}
