use std::sync::OnceLock;

use divan::Bencher;

use crate::support::{
    BenchCase, build_verifier_full_state_from_proof, emit_benchmark_stats_row, ensure_proof,
    log_proof_size_once, prepare_assets_cached, prepare_prover_iteration, run_full_verifier_once,
    run_preprocess_once, run_prover_iteration, warmup_proof,
};

fn filter_cases() -> &'static [BenchCase] {
    // Static list of filter queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases = vec![
            BenchCase {
                name: "filter_eq",
                query: r#"SELECT l_returnflag FROM lineitem WHERE l_partkey = 214"#,
                tables: &["lineitem"],
                    benchmark_suite: None,
            },
            BenchCase {
                name: "filter_lt",
                query: r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_shipdate < DATE '1998-09-01'"#,
                tables: &["lineitem"],
                    benchmark_suite: None,
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

/// Filter-by-pattern (SQL LIKE) benchmark cases spanning every factor
/// shape SweepFactors handles: single-factor prefix / suffix / infix,
/// and multi-factor patterns. Every case runs against
/// `lineitem.l_comment` from the TPC-H bench dataset.
fn filter_like_cases() -> &'static [BenchCase] {
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases: Vec<BenchCase> = vec![
            // Nation LIKE audit set — three shapes on the same column
            // (`n_name`) so the IR / prover / verifier / proof metrics
            // are directly comparable across pattern kinds. Nation is
            // ~25 rows, so these run in seconds and won't OOM the
            // dashboard host.
            BenchCase {
                name: "filter_like_prefix_nation",
                query: r#"SELECT n_name FROM nation WHERE n_name LIKE 'IN%'"#,
                tables: &["nation"],
                benchmark_suite: None,
            },
            BenchCase {
                name: "filter_like_suffix_nation",
                query: r#"SELECT n_name FROM nation WHERE n_name LIKE '%AN'"#,
                tables: &["nation"],
                benchmark_suite: None,
            },
            BenchCase {
                name: "filter_like_infix_nation",
                query: r#"SELECT n_name FROM nation WHERE n_name LIKE '%AN%'"#,
                tables: &["nation"],
                benchmark_suite: None,
            },
            // t = 1, single infix — the most common shape.
            BenchCase {
                name: "filter_like_infix",
                query: r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%green%'"#,
                tables: &["lineitem"],
                benchmark_suite: None,
            },
            // t = 1, prefix.
            BenchCase {
                name: "filter_like_prefix",
                query: r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE 'deposits%'"#,
                tables: &["lineitem"],
                benchmark_suite: None,
            },
            // t = 1, suffix.
            BenchCase {
                name: "filter_like_suffix",
                query: r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%requests'"#,
                tables: &["lineitem"],
                benchmark_suite: None,
            },
            // t = 2, two infix factors.
            BenchCase {
                name: "filter_like_two_infix",
                query: r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%bold%plate%'"#,
                tables: &["lineitem"],
                benchmark_suite: None,
            },
            // t = 2, prefix + infix.
            BenchCase {
                name: "filter_like_prefix_infix",
                query: r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE 'ideas%green%'"#,
                tables: &["lineitem"],
                benchmark_suite: None,
            },
            // t = 3, three infix factors — exercises the past-chain
            // for more than one inter-factor step.
            BenchCase {
                name: "filter_like_three_infix",
                query: r#"SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%special%packages%beans%'"#,
                tables: &["lineitem"],
                benchmark_suite: None,
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = filter_cases(), max_time = 1)]
fn bench_filter_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    let assets = prepare_assets_cached(case);
    bencher
        .with_inputs(|| prepare_prover_iteration(&assets))
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
    emit_benchmark_stats_row("bench_filter_prover", case.name);
}

#[divan::bench(args = filter_cases(), sample_size = 10)]
fn bench_filter_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: preprocess once, then time from tracking onward.
    let assets = prepare_assets_cached(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, case.query, &bench_proof);
    let state = build_verifier_full_state_from_proof(&assets, &bench_proof);
    run_preprocess_once(&state);
    bencher.bench_local(|| {
        run_full_verifier_once(&state);
    });
    emit_benchmark_stats_row("bench_filter_verifier", case.name);
}

// -----------------------------------------------------------------------------
// SQL LIKE benchmarks — routed through the MCPM gadget via
// `crates/tt-core/src/irs/nodes/plan/exprs/like.rs`. Requires
// `CHAR_LEVEL_SIDE_POLYS_ENABLED = true` at encoding time (currently
// on) and an SRS sized for the char-level side segments (bench SRS at
// `log_size = 25` is typically sufficient for lineitem.l_comment;
// smaller SRS will fail at commit time).

#[divan::bench(args = filter_like_cases(), sample_size = 1, sample_count = 1)]
fn bench_filter_like_prover(bencher: Bencher, case: BenchCase) {
    let assets = prepare_assets_cached(case);
    bencher
        .with_inputs(|| prepare_prover_iteration(&assets))
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
    emit_benchmark_stats_row("bench_filter_like_prover", case.name);
}

#[divan::bench(args = filter_like_cases(), sample_size = 10)]
fn bench_filter_like_verifier(bencher: Bencher, case: BenchCase) {
    let assets = prepare_assets_cached(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, case.query, &bench_proof);
    let state = build_verifier_full_state_from_proof(&assets, &bench_proof);
    run_preprocess_once(&state);
    bencher.bench_local(|| {
        run_full_verifier_once(&state);
    });
    emit_benchmark_stats_row("bench_filter_like_verifier", case.name);
}

