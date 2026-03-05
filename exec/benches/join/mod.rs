use std::sync::OnceLock;

use divan::Bencher;
use tokio::runtime::Runtime;

use datafusion::prelude::{JoinType, ParquetReadOptions, SessionContext, col, lit};

use crate::support::{
    BenchCase, build_verifier_state, emit_benchmark_stats_row, ensure_proof, fork_arg_verifier,
    load_proof_bytes_cached, log_proof_size_once, prepare_assets_cached, prepare_prover_iteration,
    run_arg_verifier_once, run_prover_iteration, warmup_proof,
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
                SELECT *
FROM
    customer,
    orders,
    lineitem,
    supplier,
    nation
WHERE
    c_custkey = o_custkey
    AND l_orderkey = o_orderkey
    AND l_suppkey = s_suppkey
    AND c_nationkey = s_nationkey
    AND s_nationkey = n_nationkey
    AND o_orderdate >= CAST('1994-01-01' AS date)
    AND o_orderdate < CAST('1995-01-01' AS date)
    "#,
                tables: &[
                    "orders", "customer", "lineitem", "supplier", "nation", "region",
                ],
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[derive(Clone, Copy, Debug)]
enum PlanOpVariant {
    Join,
    Project,
    Filter,
    Sort,
    GroupBy,
    Limit,
}

#[derive(Clone, Copy, Debug)]
struct PlanOpCase {
    name: &'static str,
    op: PlanOpVariant,
}

fn plan_op_cases() -> &'static [PlanOpCase] {
    static CASES: OnceLock<&'static [PlanOpCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let cases = vec![
            PlanOpCase {
                name: "df_op_join_no_collect",
                op: PlanOpVariant::Join,
            },
            PlanOpCase {
                name: "df_op_project_no_collect",
                op: PlanOpVariant::Project,
            },
            PlanOpCase {
                name: "df_op_filter_no_collect",
                op: PlanOpVariant::Filter,
            },
            PlanOpCase {
                name: "df_op_sort_no_collect",
                op: PlanOpVariant::Sort,
            },
            PlanOpCase {
                name: "df_op_groupby_no_collect",
                op: PlanOpVariant::GroupBy,
            },
            PlanOpCase {
                name: "df_op_limit_no_collect",
                op: PlanOpVariant::Limit,
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

fn rt_block_on<F: std::future::Future>(future: F) -> F::Output {
    static RT: OnceLock<Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| Runtime::new().expect("build tokio runtime for join plan bench"));
    rt.block_on(future)
}

fn build_plan_op_context() -> SessionContext {
    let ctx = SessionContext::new();
    let lineitem_path = tpch_data::bench_data_path("lineitem.parquet");
    let orders_path = tpch_data::bench_data_path("orders.parquet");
    rt_block_on(ctx.register_parquet(
        "lineitem",
        lineitem_path
            .to_str()
            .expect("lineitem parquet path must be UTF-8"),
        ParquetReadOptions::default(),
    ))
    .expect("register lineitem parquet for plan-op bench");
    rt_block_on(ctx.register_parquet(
        "orders",
        orders_path
            .to_str()
            .expect("orders parquet path must be UTF-8"),
        ParquetReadOptions::default(),
    ))
    .expect("register orders parquet for plan-op bench");
    ctx
}

fn build_plan_op_once_no_collect(ctx: &SessionContext, case: PlanOpCase) {
    let left_df = rt_block_on(ctx.table("lineitem")).expect("load lineitem dataframe");
    let plan = match case.op {
        PlanOpVariant::Join => {
            let right_df = rt_block_on(ctx.table("orders")).expect("load orders dataframe");
            left_df
                .join(
                    right_df,
                    JoinType::Inner,
                    &["l_orderkey"],
                    &["o_orderkey"],
                    None,
                )
                .expect("build join dataframe plan")
                .logical_plan()
                .clone()
        }
        PlanOpVariant::Project => left_df
            .select(vec![col("l_orderkey"), col("l_extendedprice"), col("l_discount")])
            .expect("build projection dataframe plan")
            .logical_plan()
            .clone(),
        PlanOpVariant::Filter => left_df
            .filter(col("l_discount").lt(lit(0.05_f64)))
            .expect("build filter dataframe plan")
            .logical_plan()
            .clone(),
        PlanOpVariant::Sort => left_df
            .sort(vec![col("l_shipdate").sort(true, false)])
            .expect("build sort dataframe plan")
            .logical_plan()
            .clone(),
        PlanOpVariant::GroupBy => {
            let query = "SELECT l_orderkey, SUM(l_extendedprice) AS sum_extendedprice \
                         FROM lineitem GROUP BY l_orderkey";
            rt_block_on(ctx.sql(query))
                .expect("build sql dataframe for groupby plan")
                .logical_plan()
                .clone()
        }
        PlanOpVariant::Limit => left_df
            .limit(0, Some(50))
            .expect("build limit dataframe plan")
            .logical_plan()
            .clone(),
    };
    std::hint::black_box(plan);
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

#[divan::bench(args = join_cases(), max_time = 1)]
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

#[divan::bench(args = plan_op_cases(), max_time = 2)]
fn bench_df_plan_ops_no_collect(bencher: Bencher, case: PlanOpCase) {
    // Benchmark one DataFrame operation at a time (no collect/IO execution).
    let ctx = build_plan_op_context();
    bencher.bench_local(|| {
        build_plan_op_once_no_collect(&ctx, case);
    });
    emit_benchmark_stats_row("bench_df_plan_ops_no_collect", case.name);
}
