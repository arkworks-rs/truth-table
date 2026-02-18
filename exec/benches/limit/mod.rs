use std::sync::OnceLock;

use divan::Bencher;

use crate::support::{
    BenchCase, build_verifier_state, emit_benchmark_stats_row, ensure_proof, fork_arg_verifier,
    log_proof_size_once, prepare_assets, prepare_prover_iteration, run_arg_verifier_once,
    run_prover_iteration, warmup_proof,
};

fn limit_cases() -> &'static [BenchCase] {
    // Static list of LIMIT queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases = vec![
            BenchCase {
                name: "limit_small",
                query: r#"SELECT l_suppkey FROM lineitem LIMIT 128"#,
                tables: &["lineitem"],
            },
            BenchCase {
                name: "limit_filter",
                query: r#"SELECT l_suppkey FROM lineitem WHERE l_partkey = 214 LIMIT 256"#,
                tables: &["lineitem"],
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = limit_cases(), max_time = 1)]
fn bench_limit_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    bencher
        .with_inputs(|| {
            let assets = prepare_assets(case);
            prepare_prover_iteration(&assets)
        })
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
    emit_benchmark_stats_row("bench_limit_prover", case.name);
}

#[divan::bench(args = limit_cases(), sample_size = 10)]
fn bench_limit_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: build state once, then time only run_verifier_once.
    let assets = prepare_assets(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    let state = build_verifier_state(&assets, bench_proof.proof_bytes.clone());
    bencher
        .with_inputs(|| fork_arg_verifier(&state))
        .bench_local_values(run_arg_verifier_once);
    emit_benchmark_stats_row("bench_limit_verifier", case.name);
}
