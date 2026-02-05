use std::sync::OnceLock;

use divan::Bencher;
use tpch_data::query_spec;

use crate::support::{
    BenchCase, build_verifier_full_state, ensure_proof, log_proof_size_once, prepare_assets,
    prepare_prover_iteration, run_full_verifier_once, run_preprocess_once, run_prover_iteration,
    warmup_proof,
};

fn tpch_cases() -> &'static [BenchCase] {
    // Static list of TPCH queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let q1 = query_spec(1, false);
        println!("TPCH Q1 SQL: {}", q1.sql);
        let q1_poneglyph = query_spec(1, true);
        println!("TPCH Q1 Poneglyph SQL: {}", q1_poneglyph.sql);
        let q3 = query_spec(3, false);
        println!("TPCH Q3 SQL: {}", q3.sql);
        let q3_poneglyph = query_spec(3, true);
        println!("TPCH Q3 Poneglyph SQL: {}", q3_poneglyph.sql);
        let q5 = query_spec(5, false);
        println!("TPCH Q5 SQL: {}", q5.sql);
        let q5_poneglyph = query_spec(5, true);
        println!("TPCH Q5 Poneglyph SQL: {}", q5_poneglyph.sql);
        let q8 = query_spec(8, false);
        println!("TPCH Q8 SQL: {}", q8.sql);
        let q8_poneglyph = query_spec(8, true);
        println!("TPCH Q8 Poneglyph SQL: {}", q8_poneglyph.sql);
        let q9 = query_spec(9, false);
        println!("TPCH Q9 SQL: {}", q9.sql);
        let q9_poneglyph = query_spec(9, true);
        println!("TPCH Q9 Poneglyph SQL: {}", q9_poneglyph.sql);
        let q18 = query_spec(18, false);
        println!("TPCH Q18 SQL: {}", q18.sql);
        let q18_poneglyph = query_spec(18, true);
        println!("TPCH Q18 Poneglyph SQL: {}", q18_poneglyph.sql);
        let q19 = query_spec(19, false);
        println!("TPCH Q19 SQL: {}", q19.sql);

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
fn bench_tpch_verifier_preprocess(bencher: Bencher, case: BenchCase) {
    // Benchmark only one-time verifier preprocessing (planning/gadget-planning cache fill).
    let assets = prepare_assets(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    let state = build_verifier_full_state(&assets, bench_proof.proof_bytes.clone());
    bencher.bench_local(|| {
        run_preprocess_once(&state);
    });
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_verifier_core(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark (core/steady-state): time IR passes + cryptographic
    // verification, excluding one-time preprocessing/cache warmup.
    let assets = prepare_assets(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    let state = build_verifier_full_state(&assets, bench_proof.proof_bytes.clone());
    // Preprocess once outside the timed region so this benchmark reflects steady-state.
    run_preprocess_once(&state);
    bencher.bench_local(|| {
        run_full_verifier_once(&state);
    });
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_verifier_full(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark (full): time preprocessing + steady-state verification together.
    let assets = prepare_assets(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    let state = build_verifier_full_state(&assets, bench_proof.proof_bytes.clone());
    bencher.bench_local(|| {
        run_preprocess_once(&state);
        run_full_verifier_once(&state);
    });
}
