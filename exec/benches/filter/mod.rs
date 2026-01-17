use std::sync::OnceLock;

use divan::Bencher;

use crate::support::{
    BenchCase, build_verifier_state, ensure_proof, log_proof_size_once, prepare_assets,
    run_prover_once, run_verifier_once,
};

fn filter_cases() -> &'static [BenchCase] {
    // Static list of filter queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases = vec![
            BenchCase {
                name: "filter_eq",
                query: r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R'"#,
                tables: &["lineitem"],
            },
            BenchCase {
                name: "filter_lt",
                query: r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_shipdate < DATE '1998-09-01'"#,
                tables: &["lineitem"],
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = filter_cases(), max_time = 1)]
fn bench_filter_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: run a single prove per Divan iteration.
    bencher
        .with_inputs(|| prepare_assets(case))
        .bench_local_values(|assets| {
            let _proof = run_prover_once(&assets);
        });
}

#[divan::bench(args = filter_cases(), max_time = 1)]
fn bench_filter_verifier(bencher: Bencher, case: BenchCase) {
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
