use std::sync::OnceLock;

use divan::Bencher;
use tpch_data::query_spec;

use crate::support::{
    build_verifier_full_state, emit_benchmark_stats_row, ensure_proof, load_proof_bytes_cached,
    log_proof_size_once, prepare_assets_cached, prepare_prover_iteration, run_full_verifier_once,
    run_preprocess_once, run_prover_iteration, warmup_proof, BenchCase,
};

struct TpchCaseSpec {
    name: &'static str,
    query_number: u8,
    poneglyph: bool,
}

const TPCH_CASE_SPECS: &[TpchCaseSpec] = &[
    TpchCaseSpec {
        name: "tpch_q1",
        query_number: 1,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q1_poneglyph",
        query_number: 1,
        poneglyph: true,
    },
    TpchCaseSpec {
        name: "tpch_q3_poneglyph",
        query_number: 3,
        poneglyph: true,
    },
    TpchCaseSpec {
        name: "tpch_q3",
        query_number: 3,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q5",
        query_number: 5,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q5_poneglyph",
        query_number: 5,
        poneglyph: true,
    },
    TpchCaseSpec {
        name: "tpch_q6",
        query_number: 6,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q7",
        query_number: 7,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q8_tt",
        query_number: 8,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q8_poneglyph",
        query_number: 8,
        poneglyph: true,
    },
    TpchCaseSpec {
        name: "tpch_q9_tt",
        query_number: 9,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q9_poneglyph",
        query_number: 9,
        poneglyph: true,
    },
    TpchCaseSpec {
        name: "tpch_q10",
        query_number: 10,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q12",
        query_number: 12,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q14",
        query_number: 14,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q17",
        query_number: 17,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q18_poneglyph",
        query_number: 18,
        poneglyph: true,
    },
    TpchCaseSpec {
        name: "tpch_q18",
        query_number: 18,
        poneglyph: false,
    },
    TpchCaseSpec {
        name: "tpch_q19",
        query_number: 19,
        poneglyph: false,
    },
];

fn tpch_cases() -> &'static [BenchCase] {
    // Static list of TPCH queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let mut cases = Vec::with_capacity(TPCH_CASE_SPECS.len());
        for spec in TPCH_CASE_SPECS {
            let query = query_spec(spec.query_number, spec.poneglyph);
            cases.push(BenchCase {
                name: spec.name,
                query: query.sql,
                tables: query.tables,
            });
        }
        Box::leak(cases.into_boxed_slice())
    })
}

fn prepare_verifier_state(case: BenchCase) -> crate::support::VerifierFullBenchState {
    let assets = prepare_assets_cached(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    let proof_bytes = load_proof_bytes_cached(case.name, &bench_proof);
    build_verifier_full_state(&assets, proof_bytes.as_slice())
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    let assets = prepare_assets_cached(case);
    bencher
        .with_inputs(|| prepare_prover_iteration(&assets))
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
    emit_benchmark_stats_row("bench_tpch_prover", case.name);
}

#[divan::bench(args = tpch_cases(), max_time = 0.00000001)]
fn bench_tpch_verifier_preprocess(bencher: Bencher, case: BenchCase) {
    // Benchmark only one-time verifier preprocessing (planning/gadget-planning cache fill).
    let state = prepare_verifier_state(case);
    bencher.bench_local(|| {
        run_preprocess_once(&state);
    });
    emit_benchmark_stats_row("bench_tpch_verifier_preprocess", case.name);
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
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
