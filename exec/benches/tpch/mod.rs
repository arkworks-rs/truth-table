use std::sync::OnceLock;

use divan::Bencher;
use tpch_data::query_spec;

use crate::support::{
    BenchCase, build_verifier_full_state_from_proof, cache_proof_in_memory_if_absent,
    emit_benchmark_stats_row, log_proof_size_once, prepare_assets_cached, prepare_prover_iteration,
    run_full_verifier_once, run_preprocess_once, run_prover_iteration, warmup_proof,
};

fn tpch_cases() -> &'static [BenchCase] {
    // Static list of TPCH queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let q1 = query_spec(1, false);
        let q1_poneglyph = query_spec(1, true);
        let q2 = query_spec(2, false);
        let q3 = query_spec(3, false);
        let q3_poneglyph = query_spec(3, true);
        let q4 = query_spec(4, false);
        let q5 = query_spec(5, false);
        let q5_poneglyph = query_spec(5, true);
        let q6 = query_spec(6, false);
        let q7 = query_spec(7, false);
        let q8 = query_spec(8, false);
        let q8_poneglyph = query_spec(8, true);
        let q9 = query_spec(9, false);
        let q9_poneglyph = query_spec(9, true);
        let q10 = query_spec(10, false);
        let q12 = query_spec(12, false);
        let q14 = query_spec(14, false);
        let q15 = query_spec(15, false);
        let q17 = query_spec(17, false);
        let q18 = query_spec(18, false);
        let q18_poneglyph = query_spec(18, true);
        let q19 = query_spec(19, false);
        let q20 = query_spec(20, false);

        let cases = vec![
            // BenchCase {
            //     name: "tpch_q1_tt",
            //     query: q1.sql,
            //     tables: q1.tables,
            // },
            // BenchCase {
            //     name: "tpch_q1_poneglyph",
            //     query: q1_poneglyph.sql,
            //     tables: q1_poneglyph.tables,
            // },
            // BenchCase {
            //     name: "tpch_q2_tt",
            //     query: q2.sql,
            //     tables: q2.tables,
            // },
            // BenchCase {
            //     name: "tpch_q3_poneglyph",
            //     query: q3_poneglyph.sql,
            //     tables: q3_poneglyph.tables,
            // },
            // BenchCase {
            //     name: "tpch_q3_tt",
            //     query: q3.sql,
            //     tables: q3.tables,
            // },
            // BenchCase {
            //     name: "tpch_q4_tt",
            //     query: q4.sql,
            //     tables: q4.tables,
            // },
            // BenchCase {
            //     name: "tpch_q5_tt",
            //     query: q5.sql,
            //     tables: q5.tables,
            // },
            // BenchCase {
            //     name: "tpch_q5_poneglyph",
            //     query: q5_poneglyph.sql,
            //     tables: q5_poneglyph.tables,
            // },
            // BenchCase {
            //     name: "tpch_q6_tt",
            //     query: q6.sql,
            //     tables: q6.tables,
            // },
            // BenchCase {
            //     name: "tpch_q7_tt",
            //     query: q7.sql,
            //     tables: q7.tables,
            // },
            // BenchCase {
            //     name: "tpch_q8_tt",
            //     query: q8.sql,
            //     tables: q8.tables,
            // },
            // BenchCase {
            //     name: "tpch_q8_poneglyph",
            //     query: q8_poneglyph.sql,
            //     tables: q8_poneglyph.tables,
            // },
            // BenchCase {
            //     name: "tpch_q9_tt",
            //     query: q9.sql,
            //     tables: q9.tables,
            // },
            // BenchCase {
            //     name: "tpch_q9_poneglyph",
            //     query: q9_poneglyph.sql,
            //     tables: q9_poneglyph.tables,
            // },
            // BenchCase {
            //     name: "tpch_q10_tt",
            //     query: q10.sql,
            //     tables: q10.tables,
            // },
            // BenchCase {
            //     name: "tpch_q12_tt",
            //     query: q12.sql,
            //     tables: q12.tables,
            // },
            // BenchCase {
            //     name: "tpch_q14_tt",
            //     query: q14.sql,
            //     tables: q14.tables,
            // },
            // BenchCase {
            //     name: "tpch_q15_tt",
            //     query: q15.sql,
            //     tables: q15.tables,
            // },
            // BenchCase {
            //     name: "tpch_q17_tt",
            //     query: q17.sql,
            //     tables: q17.tables,
            // },
            // BenchCase {
            //     name: "tpch_q18_poneglyph",
            //     query: q18_poneglyph.sql,
            //     tables: q18_poneglyph.tables,
            // },
            // BenchCase {
            //     name: "tpch_q18_tt",
            //     query: q18.sql,
            //     tables: q18.tables,
            // },
            // BenchCase {
            //     name: "tpch_q19_tt",
            //     query: q19.sql,
            //     tables: q19.tables,
            // },
            BenchCase {
                name: "tpch_q20_tt",
                query: q20.sql,
                tables: q20.tables,
            },
        ];
        let selected_names = selected_tpch_case_names(&cases);
        let filtered = if selected_names.is_empty() {
            cases
        } else {
            cases
                .into_iter()
                .filter(|case| selected_names.contains(&case.name))
                .collect()
        };
        Box::leak(filtered.into_boxed_slice())
    })
}

fn selected_tpch_case_names(cases: &[BenchCase]) -> Vec<&'static str> {
    let args: Vec<String> = std::env::args().collect();
    cases
        .iter()
        .filter(|case| {
            args.iter()
                .any(|arg| arg == case.name || arg.ends_with(&format!("::{}", case.name)))
        })
        .map(|case| case.name)
        .collect()
}

fn warm_selected_tpch_proofs_once() {
    static WARMED: OnceLock<()> = OnceLock::new();
    WARMED.get_or_init(|| {
        for case in tpch_cases() {
            let assets = prepare_assets_cached(*case);
            let _ = warmup_proof(&assets);
        }
    });
}

fn prepare_verifier_state(case: BenchCase) -> crate::support::VerifierFullBenchState {
    warm_selected_tpch_proofs_once();
    let assets = prepare_assets_cached(case);
    let bench_proof = warmup_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    build_verifier_full_state_from_proof(&assets, &bench_proof.proof)
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    let assets = prepare_assets_cached(case);
    bencher
        .with_inputs(|| prepare_prover_iteration(&assets))
        .bench_local_values(|iteration| {
            let proof = run_prover_iteration(iteration);
            let bench_proof = cache_proof_in_memory_if_absent(case.name, &proof);
            log_proof_size_once(case.name, &bench_proof);
        });
    emit_benchmark_stats_row("bench_tpch_prover", case.name);
}

#[divan::bench(args = tpch_cases(), max_time = 10)]
fn bench_tpch_verifier_preprocess(bencher: Bencher, case: BenchCase) {
    // Benchmark only one-time verifier preprocessing (planning/gadget-planning cache fill).
    let state = prepare_verifier_state(case);
    bencher.bench_local(|| {
        run_preprocess_once(&state);
    });
    emit_benchmark_stats_row("bench_tpch_verifier_preprocess", case.name);
}

#[divan::bench(args = tpch_cases(), max_time = 10)]
fn bench_tpch_verifier_core(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark (core/steady-state): time IR passes + cryptographic
    // verification, excluding one-time preprocessing/cache warmup.
    let state = prepare_verifier_state(case);
    // Preprocess once outside the timed region so this benchmark reflects steady-state.
    run_preprocess_once(&state);
    bencher.bench_local(|| {
        run_full_verifier_once(&state);
    });
    emit_benchmark_stats_row("bench_tpch_verifier_core", case.name);
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_verifier_full(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark (full): time preprocessing + steady-state verification together.
    let state = prepare_verifier_state(case);
    bencher.bench_local(|| {
        run_preprocess_once(&state);
        run_full_verifier_once(&state);
    });
    emit_benchmark_stats_row("bench_tpch_verifier_full", case.name);
}
