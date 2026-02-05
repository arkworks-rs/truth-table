use std::sync::OnceLock;

use divan::Bencher;
use tpch_data::query_spec;

use crate::support::{
    BenchCase, build_verifier_state, ensure_proof, log_proof_size_once, prepare_assets,
    prepare_prover_iteration, run_prover_iteration, run_verifier_once, warmup_proof,
};

fn tpch_cases() -> &'static [BenchCase] {
    // Static list of TPCH queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let q1 = query_spec(1, false);
        let q1_poneglyph = query_spec(1, true);
        let q3 = query_spec(3, false);
        let q3_poneglyph = query_spec(3, true);
        let q5 = query_spec(5, false);
        let q5_poneglyph = query_spec(5, true);
        let q8 = query_spec(8, false);
        let q8_poneglyph = query_spec(8, true);
        let q9 = query_spec(9, false);
        let q9_poneglyph = query_spec(9, true);
        let q18 = query_spec(18, false);
        let q18_poneglyph = query_spec(18, true);
        let q19 = query_spec(19, false);

        let cases = vec![
            BenchCase {
                name: "tpch_q1",
                query: q1.sql,
                tables: q1.tables,
            },
            BenchCase {
                name: "tpch_q1_poneglyph",
                query: q1_poneglyph.sql,
                tables: q1_poneglyph.tables,
            },
            BenchCase {
                name: "tpch_q3_poneglyph",
                query: q3_poneglyph.sql,
                tables: q3_poneglyph.tables,
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
            BenchCase {
                name: "tpch_q5_poneglyph",
                query: q5_poneglyph.sql,
                tables: q5_poneglyph.tables,
            },
            BenchCase {
                name: "tpch_q8_tt",
                query: q8.sql,
                tables: q8.tables,
            },
            BenchCase {
                name: "tpch_q8_poneglyph",
                query: q8_poneglyph.sql,
                tables: q8_poneglyph.tables,
            },
            BenchCase {
                name: "tpch_q9_tt",
                query: q9.sql,
                tables: q9.tables,
            },
            BenchCase {
                name: "tpch_q9_poneglyph",
                query: q9_poneglyph.sql,
                tables: q9_poneglyph.tables,
            },
            BenchCase {
                name: "tpch_q18_poneglyph",
                query: q18_poneglyph.sql,
                tables: q18_poneglyph.tables,
            },
            BenchCase {
                name: "tpch_q18",
                query: q18.sql,
                tables: q18.tables,
            },
            BenchCase {
                name: "tpch_q19",
                query: q19.sql,
                tables: q19.tables,
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    bencher
        .with_inputs(|| {
            let assets = prepare_assets(case);
            prepare_prover_iteration(&assets)
        })
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: require a warm cache, then reuse cached proof bytes.
    bencher
        .with_inputs(|| {
            let assets = prepare_assets(case);
            let _ = warmup_proof(&assets);
            let bench_proof = ensure_proof(&assets);
            log_proof_size_once(case.name, &bench_proof);
            build_verifier_state(&assets, bench_proof.proof_bytes.clone())
        })
        .bench_local_values(|state| {
            run_verifier_once(&state);
        });
}
