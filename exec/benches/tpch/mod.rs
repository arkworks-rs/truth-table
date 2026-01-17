use std::sync::OnceLock;

use divan::Bencher;
use tpch_data::query_spec;

use crate::support::{
    BenchCase, build_verifier_state, ensure_proof, log_proof_size_once, prepare_assets,
    run_prover_once, run_verifier_once,
};

fn tpch_cases() -> &'static [BenchCase] {
    // Static list of TPCH queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let q1 = query_spec(1);
        let q3 = query_spec(3);
        let q5 = query_spec(5);

        let cases = vec![
            BenchCase {
                name: "tpch_q1",
                query: q1.sql,
                tables: q1.tables,
            },
            BenchCase {
                name: "tpch_q3",
                query: q3.sql,
                tables: q3.tables,
            },
            BenchCase {
                name: "tpch_q5",
                query: q5.sql,
                tables: q5.tables,
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: run a single prove per Divan iteration.
    bencher
        .with_inputs(|| prepare_assets(case))
        .bench_local_values(|assets| {
            let _proof = run_prover_once(&assets);
        });
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_verifier(bencher: Bencher, case: BenchCase) {
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
