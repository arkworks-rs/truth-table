use std::sync::OnceLock;

use divan::Bencher;

use crate::support::{
    build_verifier_state, emit_benchmark_stats_row, ensure_proof, fork_arg_verifier,
    load_proof_bytes_cached, log_proof_size_once, prepare_assets_cached, prepare_prover_iteration,
    run_arg_verifier_once, run_prover_iteration, warmup_proof, BenchCase,
};

fn join_cases() -> &'static [BenchCase] {
    // Static list of simple inner-join queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases = vec![
            // BenchCase {
            //     name: "join_supplier_customer_small_many_to_many",
            //     query: r#"
            //         SELECT s.s_suppkey, s.s_nationkey, c.c_custkey
            //         FROM supplier s
            //         INNER JOIN customer c
            //             ON s.s_nationkey = c.c_nationkey
            //     "#,
            //     tables: &["supplier", "customer"],
            // },
            // BenchCase {
            //     name: "join_partsupp_self_medium_many_to_many",
            //     query: r#"
            //         SELECT ps1.ps_partkey, ps1.ps_suppkey, ps2.ps_suppkey
            //         FROM partsupp ps1
            //         INNER JOIN partsupp ps2
            //             ON ps1.ps_partkey = ps2.ps_partkey
            //     "#,
            //     tables: &["partsupp"],
            // },
            // BenchCase {
            //     name: "join_lineitem_self_large_many_to_many",
            //     query: r#"
            //         SELECT l1.l_orderkey, l1.l_linenumber, l2.l_linenumber
            //         FROM lineitem l1
            //         INNER JOIN lineitem l2
            //             ON l1.l_orderkey = l2.l_orderkey
            //     "#,
            //     tables: &["lineitem"],
            // },
            // BenchCase {
            //     name: "join_supplier_nation_small_one_to_many",
            //     query: r#"
            //         SELECT s.s_suppkey, s.s_nationkey, n.n_name
            //         FROM supplier s
            //         INNER JOIN nation n
            //             ON s.s_nationkey = n.n_nationkey
            //     "#,
            //     tables: &["supplier", "nation"],
            // },
            // BenchCase {
            //     name: "join_orders_customer_medium_one_to_many",
            //     query: r#"
            //         SELECT o.o_orderkey, o.o_custkey, c.c_nationkey
            //         FROM orders o
            //         INNER JOIN customer c
            //             ON o.o_custkey = c.c_custkey
            //     "#,
            //     tables: &["orders", "customer"],
            // },
            // BenchCase {
            //     name: "join_lineitem_orders_large_one_to_many",
            //     query: r#"
            //         SELECT l.l_orderkey, l.l_partkey, o.o_orderpriority
            //         FROM lineitem l
            //         INNER JOIN orders o
            //             ON l.l_orderkey = o.o_orderkey
            //     "#,
            //     tables: &["lineitem", "orders"],
            // },
            // BenchCase {
            //     name: "join_partsupp_self_small_composite_key",
            //     query: r#"
            //         SELECT ps1.ps_partkey, ps1.ps_suppkey, ps2.ps_supplycost
            //         FROM partsupp ps1
            //         INNER JOIN partsupp ps2
            //             ON ps1.ps_partkey = ps2.ps_partkey
            //            AND ps1.ps_suppkey = ps2.ps_suppkey
            //     "#,
            //     tables: &["partsupp"],
            // },
            // BenchCase {
            //     name: "join_lineitem_partsupp_medium_composite_key",
            //     query: r#"
            //         SELECT l.l_orderkey, l.l_partkey, l.l_suppkey, ps.ps_supplycost
            //         FROM lineitem l
            //         INNER JOIN partsupp ps
            //             ON l.l_partkey = ps.ps_partkey
            //            AND l.l_suppkey = ps.ps_suppkey
            //     "#,
            //     tables: &["lineitem", "partsupp"],
            // },
            BenchCase {
                name: "join_lineitem_self_large_composite_key",
                query: r#"
                    SELECT l1.l_orderkey, l1.l_partkey, l1.l_linenumber, l2.l_linenumber
                    FROM lineitem l1
                    INNER JOIN lineitem l2
                        ON l1.l_orderkey = l2.l_orderkey
                       AND l1.l_partkey = l2.l_partkey
                "#,
                tables: &["lineitem"],
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = join_cases(), max_time = 1)]
fn bench_join_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    let assets = prepare_assets_cached(case);
    bencher
        .with_inputs(|| prepare_prover_iteration(&assets))
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
    emit_benchmark_stats_row("bench_join_prover", case.name);
}

#[divan::bench(args = join_cases(), sample_size = 10)]
fn bench_join_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: build state once, then time only run_verifier_once.
    let assets = prepare_assets_cached(case);
    let _ = warmup_proof(&assets);
    let bench_proof = ensure_proof(&assets);
    log_proof_size_once(case.name, &bench_proof);
    let proof_bytes = load_proof_bytes_cached(case.name, &bench_proof);
    let state = build_verifier_state(&assets, proof_bytes.as_slice());
    bencher
        .with_inputs(|| fork_arg_verifier(&state))
        .bench_local_values(run_arg_verifier_once);
    emit_benchmark_stats_row("bench_join_verifier", case.name);
}
