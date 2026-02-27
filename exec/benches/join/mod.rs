use std::sync::OnceLock;

use divan::Bencher;

use crate::support::{
    BenchCase, build_verifier_state, emit_benchmark_stats_row, ensure_proof, fork_arg_verifier,
    log_proof_size_once, prepare_assets, prepare_prover_iteration, run_arg_verifier_once,
    run_prover_iteration, warmup_proof,
};

fn join_cases() -> &'static [BenchCase] {
    // Static list of simple inner-join queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases = vec![
            BenchCase {
                name: "join_lineitem_orders_basic",
                query: r#"
                    SELECT l.l_orderkey, l.l_partkey, o.o_orderpriority
                    FROM lineitem l
                    INNER JOIN orders o
                        ON l.l_orderkey = o.o_orderkey
                "#,
                tables: &["lineitem", "orders"],
            },
            BenchCase {
                name: "join_lineitem_orders_filtered",
                query: r#"
                    SELECT l.l_orderkey, o.o_orderdate
                    FROM lineitem l
                    INNER JOIN orders o
                        ON l.l_orderkey = o.o_orderkey
                    WHERE l.l_shipdate < DATE '1998-09-01'
                "#,
                tables: &["lineitem", "orders"],
            },
            BenchCase {
                name: "join_orders_customer_basic",
                query: r#"
                    SELECT o.o_orderkey, c.c_nationkey
                    FROM orders o
                    INNER JOIN customer c
                        ON o.o_custkey = c.c_custkey
                "#,
                tables: &["orders", "customer"],
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = join_cases(), max_time = 1)]
fn bench_join_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    bencher
        .with_inputs(|| {
            let assets = prepare_assets(case);
            prepare_prover_iteration(&assets)
        })
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
    emit_benchmark_stats_row("bench_join_prover", case.name);
}

#[divan::bench(args = join_cases(), max_time = 1)]
fn bench_join_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: build state once, then time only run_verifier_once.
    let assets = prepare_assets(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    let state = build_verifier_state(&assets, bench_proof.proof_bytes.clone());
    bencher
        .with_inputs(|| fork_arg_verifier(&state))
        .bench_local_values(run_arg_verifier_once);
    emit_benchmark_stats_row("bench_join_verifier", case.name);
}
