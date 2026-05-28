//! Three-config ablation benchmark crossing the pp_optimizer (PK-FK join
//! specialization) and the data_dependent_lp_optimizer (rematerialize):
//!
//!   - `..._all_off`           — both empty. Every join stays `MANY_TO_MANY`
//!                               and no rematerialize wrappers are emitted.
//!   - `..._pkfk_on_remat_off` — pp_optimizer enabled, data-dependent LP
//!                               optimizer empty (isolates PK-FK gain).
//!   - `..._pkfk_off_remat_on` — pp_optimizer empty, data-dependent LP
//!                               optimizer enabled (isolates rematerialize
//!                               gain).
//!
//! `all_on` is intentionally omitted: it is identical to the production
//! wiring, so the baseline `tpch` bench already covers it.
//!
//! Each variant runs the same three sub-benches as `tpch::`: `prover`,
//! `verifier_crypto`, and `verifier_full`. The proof cache key is the bench
//! case name, so each (query, config) combination caches its own proof. Both
//! the prover (via `ProveBuilder::with_*_rules`) and the verifier (via
//! `build_verifier_full_state_from_proof_with_pp_rules`) get the same rule
//! lists.

use std::sync::Arc;

use divan::Bencher;
use proof_planner::data_dependent_lp_optimizer::{
    DataDependentOptimizationRule, rules as data_dependent_rules,
};
use proof_planner::pp_optimizer::{ProofPlanOptimizerRule, rules as pp_rules};
use tpch_data::query_spec;

use crate::support::{
    B, BenchCase, build_verifier_full_state_from_proof_with_pp_rules,
    cache_proof_in_memory_if_absent, emit_benchmark_stats_row, ensure_proof, log_proof_size_once,
    prepare_assets_cached, prepare_prover_iteration_with_rules, run_full_verifier_once,
    run_preprocess_once, run_prover_iteration,
};

#[derive(Clone, Copy)]
pub enum OptConfig {
    AllOff,
    PkFkOnRematOff,
    PkFkOffRematOn,
}

impl OptConfig {
    /// Data-dependent LP optimizer rule list: defaults when rematerialize is
    /// enabled by this config, empty otherwise.
    fn data_dependent_rules(self) -> Vec<Arc<dyn DataDependentOptimizationRule>> {
        match self {
            OptConfig::PkFkOffRematOn => data_dependent_rules(),
            OptConfig::AllOff | OptConfig::PkFkOnRematOff => vec![],
        }
    }

    /// Proof-plan optimizer rule list: defaults when PK-FK is enabled by
    /// this config, empty otherwise.
    fn pp_rules(self) -> Vec<Arc<dyn ProofPlanOptimizerRule<B>>> {
        match self {
            OptConfig::PkFkOnRematOff => pp_rules::<B>(),
            OptConfig::AllOff | OptConfig::PkFkOffRematOn => vec![],
        }
    }
}

fn prepare_verifier_state(
    case: BenchCase,
    config: OptConfig,
) -> crate::support::VerifierFullBenchState {
    // Proof cache is keyed by case name, so each (query, config) caches
    // independently. The prover sub-bench runs first within a single divan
    // invocation and populates the cache; the verifier sub-benches then read
    // it. The verifier must use the same pp rule list as the prover so both
    // sides agree on each join's mode.
    let assets = prepare_assets_cached(case);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, case.query, &bench_proof);
    build_verifier_full_state_from_proof_with_pp_rules(&assets, &bench_proof, config.pp_rules())
}

macro_rules! define_optall_case_benches {
    ($module:ident, $name:literal, $query_num:literal, $config:expr) => {
        mod $module {
            use super::*;

            fn case() -> BenchCase {
                let spec = query_spec($query_num, false);
                BenchCase {
                    name: $name,
                    query: spec.sql,
                    tables: spec.tables,
                    benchmark_suite: Some(concat!(
                        "TPC-H Q",
                        stringify!($query_num),
                        " (optall)"
                    )),
                }
            }

            #[divan::bench(max_time = 1)]
            fn prover(bencher: Bencher) {
                let case = case();
                let config: OptConfig = $config;
                let assets = prepare_assets_cached(case);
                bencher
                    .with_inputs(|| {
                        prepare_prover_iteration_with_rules(
                            &assets,
                            config.data_dependent_rules(),
                            config.pp_rules(),
                        )
                    })
                    .bench_local_values(|iteration| {
                        let (output_memtable, proof) = run_prover_iteration(iteration);
                        let bench_proof =
                            cache_proof_in_memory_if_absent(case.name, output_memtable, &proof);
                        log_proof_size_once(case.name, case.query, &bench_proof);
                    });
                emit_benchmark_stats_row("bench_tpch_optall_prover", case.name);
            }

            #[divan::bench(sample_count = 100, sample_size = 1)]
            fn verifier_crypto(bencher: Bencher) {
                let case = case();
                let config: OptConfig = $config;
                let state = prepare_verifier_state(case, config);
                run_preprocess_once(&state);
                bencher.bench_local(|| {
                    run_full_verifier_once(&state);
                });
                emit_benchmark_stats_row("bench_tpch_optall_verifier_crypto", case.name);
            }

            #[divan::bench(sample_count = 100, sample_size = 1)]
            fn verifier_full(bencher: Bencher) {
                let case = case();
                let config: OptConfig = $config;
                let state = prepare_verifier_state(case, config);
                bencher.bench_local(|| {
                    run_preprocess_once(&state);
                    run_full_verifier_once(&state);
                });
                emit_benchmark_stats_row("bench_tpch_optall_verifier_full", case.name);
            }
        }
    };
}

macro_rules! optall_query {
    ($q:literal,
     $off_m:ident, $pkof_m:ident, $pkfo_m:ident,
     $off_n:literal, $pkof_n:literal, $pkfo_n:literal) => {
        define_optall_case_benches!($off_m,  $off_n,  $q, OptConfig::AllOff);
        define_optall_case_benches!($pkof_m, $pkof_n, $q, OptConfig::PkFkOnRematOff);
        define_optall_case_benches!($pkfo_m, $pkfo_n, $q, OptConfig::PkFkOffRematOn);
    };
}

optall_query!( 1, q1_all_off,  q1_pkfk_on_remat_off,  q1_pkfk_off_remat_on,
              "tpch_q1_tt_all_off",  "tpch_q1_tt_pkfk_on_remat_off",  "tpch_q1_tt_pkfk_off_remat_on");
optall_query!( 2, q2_all_off,  q2_pkfk_on_remat_off,  q2_pkfk_off_remat_on,
              "tpch_q2_tt_all_off",  "tpch_q2_tt_pkfk_on_remat_off",  "tpch_q2_tt_pkfk_off_remat_on");
optall_query!( 3, q3_all_off,  q3_pkfk_on_remat_off,  q3_pkfk_off_remat_on,
              "tpch_q3_tt_all_off",  "tpch_q3_tt_pkfk_on_remat_off",  "tpch_q3_tt_pkfk_off_remat_on");
optall_query!( 4, q4_all_off,  q4_pkfk_on_remat_off,  q4_pkfk_off_remat_on,
              "tpch_q4_tt_all_off",  "tpch_q4_tt_pkfk_on_remat_off",  "tpch_q4_tt_pkfk_off_remat_on");
optall_query!( 5, q5_all_off,  q5_pkfk_on_remat_off,  q5_pkfk_off_remat_on,
              "tpch_q5_tt_all_off",  "tpch_q5_tt_pkfk_on_remat_off",  "tpch_q5_tt_pkfk_off_remat_on");
optall_query!( 6, q6_all_off,  q6_pkfk_on_remat_off,  q6_pkfk_off_remat_on,
              "tpch_q6_tt_all_off",  "tpch_q6_tt_pkfk_on_remat_off",  "tpch_q6_tt_pkfk_off_remat_on");
optall_query!( 7, q7_all_off,  q7_pkfk_on_remat_off,  q7_pkfk_off_remat_on,
              "tpch_q7_tt_all_off",  "tpch_q7_tt_pkfk_on_remat_off",  "tpch_q7_tt_pkfk_off_remat_on");
optall_query!( 8, q8_all_off,  q8_pkfk_on_remat_off,  q8_pkfk_off_remat_on,
              "tpch_q8_tt_all_off",  "tpch_q8_tt_pkfk_on_remat_off",  "tpch_q8_tt_pkfk_off_remat_on");
optall_query!( 9, q9_all_off,  q9_pkfk_on_remat_off,  q9_pkfk_off_remat_on,
              "tpch_q9_tt_all_off",  "tpch_q9_tt_pkfk_on_remat_off",  "tpch_q9_tt_pkfk_off_remat_on");
optall_query!(10, q10_all_off, q10_pkfk_on_remat_off, q10_pkfk_off_remat_on,
              "tpch_q10_tt_all_off", "tpch_q10_tt_pkfk_on_remat_off", "tpch_q10_tt_pkfk_off_remat_on");
optall_query!(12, q12_all_off, q12_pkfk_on_remat_off, q12_pkfk_off_remat_on,
              "tpch_q12_tt_all_off", "tpch_q12_tt_pkfk_on_remat_off", "tpch_q12_tt_pkfk_off_remat_on");
optall_query!(14, q14_all_off, q14_pkfk_on_remat_off, q14_pkfk_off_remat_on,
              "tpch_q14_tt_all_off", "tpch_q14_tt_pkfk_on_remat_off", "tpch_q14_tt_pkfk_off_remat_on");
optall_query!(15, q15_all_off, q15_pkfk_on_remat_off, q15_pkfk_off_remat_on,
              "tpch_q15_tt_all_off", "tpch_q15_tt_pkfk_on_remat_off", "tpch_q15_tt_pkfk_off_remat_on");
optall_query!(17, q17_all_off, q17_pkfk_on_remat_off, q17_pkfk_off_remat_on,
              "tpch_q17_tt_all_off", "tpch_q17_tt_pkfk_on_remat_off", "tpch_q17_tt_pkfk_off_remat_on");
optall_query!(18, q18_all_off, q18_pkfk_on_remat_off, q18_pkfk_off_remat_on,
              "tpch_q18_tt_all_off", "tpch_q18_tt_pkfk_on_remat_off", "tpch_q18_tt_pkfk_off_remat_on");
optall_query!(19, q19_all_off, q19_pkfk_on_remat_off, q19_pkfk_off_remat_on,
              "tpch_q19_tt_all_off", "tpch_q19_tt_pkfk_on_remat_off", "tpch_q19_tt_pkfk_off_remat_on");
optall_query!(20, q20_all_off, q20_pkfk_on_remat_off, q20_pkfk_off_remat_on,
              "tpch_q20_tt_all_off", "tpch_q20_tt_pkfk_on_remat_off", "tpch_q20_tt_pkfk_off_remat_on");
