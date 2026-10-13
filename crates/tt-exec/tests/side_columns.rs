#![cfg(feature = "test-utils")]

//! `Tree::required_side_columns` decides which string columns get side polys
//! (`__chars`, `__orig_ind`, `__int_ind`, `__bnd`) encoded, committed and
//! tracked. It must name exactly the columns consumed by white-box string
//! gadgets (LIKE), so a query without one loads no auxiliary column (paper:
//! "Dropping Auxiliary Columns").

use std::collections::BTreeSet;

use datafusion::prelude::{ParquetReadOptions, SessionContext};
use front_end::shared::TTSharedConfig;
use tt_core::irs::shared_ir::EmptyIr;
use tt_exec::backend::BenchBackend;
use tt_exec::test_utils::resolve_parquet_path;

type B = BenchBackend;

/// The side-column set of the query's IR, built through the shared pipeline
/// the prover and the verifier both run.
async fn required_side_columns_for(sql: &str, tables: &[&str]) -> BTreeSet<String> {
    let ctx = SessionContext::new();
    for table in tables {
        let path = resolve_parquet_path(table).expect("test parquet for table");
        ctx.register_parquet(
            *table,
            path.to_str().expect("parquet path must be valid UTF-8"),
            ParquetReadOptions::default(),
        )
        .await
        .expect("register parquet table");
    }
    let shared = TTSharedConfig::<B>::with_defaults(ctx);
    let lp = shared.query_to_lp(sql).await;
    let lp = shared.analyze_lp(lp).await;
    let lp = shared.optimize_lp(lp).await;
    let ir = EmptyIr::<B>::from_logical_plan(&lp);
    let ir = shared.pp_optimizer().optimize(ir);
    ir.tree().required_side_columns()
}

/// Every TPC-H query in the benchmark suite (`_tt` and `_pgn` variants) is
/// LIKE-free, so none may load auxiliary columns.
#[tokio::test]
async fn tpch_bench_queries_require_no_side_columns() {
    // Mirrors the (query_nr, poneglyph) pairs in benches/tpch/mod.rs.
    let tt_queries: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 17, 18, 19, 20];
    let pgn_queries: &[u8] = &[1, 3, 5, 8, 9, 18];
    for &(numbers, poneglyph) in &[(tt_queries, false), (pgn_queries, true)] {
        for &number in numbers {
            let spec = tpch_data::query_spec(number, poneglyph);
            let cols = required_side_columns_for(spec.sql, spec.tables).await;
            assert!(
                cols.is_empty(),
                "TPC-H q{number} (poneglyph={poneglyph}) has no LIKE but would \
                 load side columns {cols:?}"
            );
        }
    }
}

/// A LIKE needs side polys for its bound column and for no other string
/// column of the table.
#[tokio::test]
async fn like_query_requires_exactly_its_column() {
    let cols = required_side_columns_for(
        r#"SELECT n_name FROM nation WHERE n_comment LIKE '%haggle%'"#,
        &["nation"],
    )
    .await;
    assert_eq!(cols, BTreeSet::from(["n_comment".to_string()]));
}

/// String equality uses the hash column only.
#[tokio::test]
async fn equality_filter_requires_no_side_columns() {
    let cols = required_side_columns_for(
        r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R'"#,
        &["lineitem"],
    )
    .await;
    assert!(
        cols.is_empty(),
        "equality filter would load side columns {cols:?}"
    );
}

/// A bare `Like` IR node for `n_comment LIKE '<pattern>'`. Built with
/// `Tree::from_expr` because the optimizer simplifies a wildcard-only LIKE
/// away before the SQL pipeline lowers it.
fn like_tree(pattern: &str) -> tt_core::irs::tree::Tree<B> {
    use datafusion::logical_expr::{Expr, Like};
    use datafusion::prelude::{col, lit};
    let like = Expr::Like(Like::new(
        false,
        Box::new(col("n_comment")),
        Box::new(lit(pattern)),
        None,
        false,
    ));
    tt_core::irs::tree::Tree::<B>::from_expr(&like, None, Vec::new())
}

#[test]
fn like_node_requires_its_column() {
    assert_eq!(
        like_tree("%haggle%").required_side_columns(),
        BTreeSet::from(["n_comment".to_string()])
    );
}

/// A wildcard-only pattern folds to a constant and reads no side segment, so
/// it must not require side columns.
#[test]
fn wildcard_only_like_requires_no_side_columns() {
    for pattern in ["", "%", "%%"] {
        let cols = like_tree(pattern).required_side_columns();
        assert!(
            cols.is_empty(),
            "wildcard-only LIKE '{pattern}' would load side columns {cols:?}"
        );
    }
}
