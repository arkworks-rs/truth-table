use divan::Bencher;
use tpch_data::{Variant, query_spec};

use crate::support::{
    BenchCase, build_verifier_full_state_from_proof, cache_proof_in_memory_if_absent,
    emit_benchmark_stats_row, ensure_proof, log_proof_size_once, prepare_assets_cached,
    prepare_prover_iteration, run_full_verifier_once, run_preprocess_once, run_prover_iteration,
};

fn prepare_verifier_state(case: BenchCase) -> crate::support::VerifierFullBenchState {
    let assets = prepare_assets_cached(case);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, case.query, &bench_proof);
    build_verifier_full_state_from_proof(&assets, &bench_proof)
}

macro_rules! define_tpch_case_benches {
    ($module:ident, $name:literal, $query_num:literal, Tt) => {
        define_tpch_case_benches!(@inner $module, $name, $query_num, Tt,
            concat!("TPC-H Q", stringify!($query_num)));
    };
    ($module:ident, $name:literal, $query_num:literal, Tt2) => {
        define_tpch_case_benches!(@inner $module, $name, $query_num, Tt2,
            concat!("TPC-H Q", stringify!($query_num), " (strings)"));
    };
    ($module:ident, $name:literal, $query_num:literal, Pgn) => {
        define_tpch_case_benches!(@inner $module, $name, $query_num, Pgn,
            concat!("TPC-H Q", stringify!($query_num), " (Poneglyph)"));
    };
    (@inner $module:ident, $name:literal, $query_num:literal, $variant:ident, $suite:expr) => {
        mod $module {
            use super::*;

            fn case() -> BenchCase {
                let spec = query_spec($query_num, Variant::$variant);
                BenchCase {
                    name: $name,
                    query: spec.sql,
                    tables: spec.tables,
                    benchmark_suite: Some($suite),
                }
            }

            #[divan::bench(max_time = 1)]
            fn prover(bencher: Bencher) {
                let case = case();
                let assets = prepare_assets_cached(case);
                bencher
                    .with_inputs(|| prepare_prover_iteration(&assets))
                    .bench_local_values(|iteration| {
                        let (output_memtable, proof) = run_prover_iteration(iteration);
                        let bench_proof =
                            cache_proof_in_memory_if_absent(case.name, output_memtable, &proof);
                        log_proof_size_once(case.name, case.query, &bench_proof);
                    });
                emit_benchmark_stats_row("bench_tpch_prover", case.name);
            }

            #[divan::bench(sample_count = 100, sample_size = 1)]
            fn verifier_crypto(bencher: Bencher) {
                let case = case();
                let state = prepare_verifier_state(case);
                run_preprocess_once(&state);
                bencher.bench_local(|| {
                    run_full_verifier_once(&state);
                });
                emit_benchmark_stats_row("bench_tpch_verifier_crypto", case.name);
            }

            #[divan::bench(sample_count = 100, sample_size = 1)]
            fn verifier_full(bencher: Bencher) {
                let case = case();
                let state = prepare_verifier_state(case);
                bencher.bench_local(|| {
                    run_preprocess_once(&state);
                    run_full_verifier_once(&state);
                });
                emit_benchmark_stats_row("bench_tpch_verifier_full", case.name);
            }
        }
    };
}

define_tpch_case_benches!(tpch_q1_tt, "tpch_q1_tt", 1, Tt);
define_tpch_case_benches!(tpch_q2_tt, "tpch_q2_tt", 2, Tt);
define_tpch_case_benches!(tpch_q3_tt, "tpch_q3_tt", 3, Tt);
define_tpch_case_benches!(tpch_q4_tt, "tpch_q4_tt", 4, Tt);
define_tpch_case_benches!(tpch_q5_tt, "tpch_q5_tt", 5, Tt);
define_tpch_case_benches!(tpch_q6_tt, "tpch_q6_tt", 6, Tt);
define_tpch_case_benches!(tpch_q7_tt, "tpch_q7_tt", 7, Tt);
define_tpch_case_benches!(tpch_q8_tt, "tpch_q8_tt", 8, Tt);
define_tpch_case_benches!(tpch_q9_tt, "tpch_q9_tt", 9, Tt);
define_tpch_case_benches!(tpch_q10_tt, "tpch_q10_tt", 10, Tt);
define_tpch_case_benches!(tpch_q12_tt, "tpch_q12_tt", 12, Tt);
define_tpch_case_benches!(tpch_q14_tt, "tpch_q14_tt", 14, Tt);
define_tpch_case_benches!(tpch_q15_tt, "tpch_q15_tt", 15, Tt);
define_tpch_case_benches!(tpch_q17_tt, "tpch_q17_tt", 17, Tt);
define_tpch_case_benches!(tpch_q18_tt, "tpch_q18_tt", 18, Tt);
define_tpch_case_benches!(tpch_q19_tt, "tpch_q19_tt", 19, Tt);
define_tpch_case_benches!(tpch_q20_tt, "tpch_q20_tt", 20, Tt);

// The `_tt` queries whose rewrite drops a string predicate, with it put back
// (`tpch_data::TT_2_QUERIES`).
define_tpch_case_benches!(tpch_q2_tt_2, "tpch_q2_tt_2", 2, Tt2);
define_tpch_case_benches!(tpch_q9_tt_2, "tpch_q9_tt_2", 9, Tt2);
define_tpch_case_benches!(tpch_q14_tt_2, "tpch_q14_tt_2", 14, Tt2);
define_tpch_case_benches!(tpch_q20_tt_2, "tpch_q20_tt_2", 20, Tt2);

// Poneglyph variants for the subset of queries that have a `*_PGN_SQL`
// definition in tt-tpch-data (Q1/Q3/Q5/Q8/Q9/Q18).
define_tpch_case_benches!(tpch_q1_pgn, "tpch_q1_pgn", 1, Pgn);
define_tpch_case_benches!(tpch_q3_pgn, "tpch_q3_pgn", 3, Pgn);
define_tpch_case_benches!(tpch_q5_pgn, "tpch_q5_pgn", 5, Pgn);
define_tpch_case_benches!(tpch_q8_pgn, "tpch_q8_pgn", 8, Pgn);
define_tpch_case_benches!(tpch_q9_pgn, "tpch_q9_pgn", 9, Pgn);
define_tpch_case_benches!(tpch_q18_pgn, "tpch_q18_pgn", 18, Pgn);
