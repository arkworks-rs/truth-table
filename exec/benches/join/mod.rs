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
