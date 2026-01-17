use std::sync::OnceLock;

use divan::Bencher;

use crate::support::{
    BenchCase, build_verifier_state, ensure_proof, log_proof_size_once, prepare_assets,
    run_prover_once, run_verifier_once,
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
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = aggregate_cases(), max_time = 1)]
fn bench_aggregate_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: run a single prove per Divan iteration.
    bencher
        .with_inputs(|| prepare_assets(case))
        .bench_local_values(|assets| {
            let _proof = run_prover_once(&assets);
        });
}

#[divan::bench(args = aggregate_cases(), max_time = 1)]
fn bench_aggregate_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: reuse cached proof bytes (or create once on demand).
    bencher
        .with_inputs(|| {
            let assets = prepare_assets(case);
            let bench_proof = ensure_proof(&assets);
            log_proof_size_once(case.name, bench_proof.proof_bytes.len());
            build_verifier_state(&assets, bench_proof.proof_bytes.clone())
        })
        .bench_local_values(|state| {
            run_verifier_once(&state);
        });
}
