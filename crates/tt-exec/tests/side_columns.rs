#![cfg(feature = "test-utils")]

//! Plan-level tests for auxiliary (char-level side poly) column pruning.
//!
//! `Tree::required_side_columns` decides which string columns get side polys
//! (`__chars`, `__orig_ind`, `__int_ind`, `__bnd`) encoded, committed, and
//! tracked. It must name exactly the columns consumed by white-box string
//! gadgets (LIKE) — and nothing else, so queries without white-box string
//! operations never load auxiliary columns at all (paper: "Dropping
//! Auxiliary Columns").
//!
//! These tests replay the shared logical-plan pipeline (plan → analyze →
//! optimize → IR → proof-plan optimize) exactly as prover and verifier do,
//! then assert on the resulting set.

use std::collections::BTreeSet;

use datafusion::prelude::{ParquetReadOptions, SessionContext};
use front_end::shared::TTSharedConfig;
use tt_core::irs::shared_ir::EmptyIr;
use tt_exec::backend::BenchBackend;
use tt_exec::test_utils::resolve_parquet_path;

type B = BenchBackend;

/// Build the query's IR the way both prover and verifier do, and return the
/// side-column set the pipeline will use.
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

/// Every TPC-H query in the benchmark suite (both `_tt` and `_pgn`
/// variants) is LIKE-free, so none of them may load auxiliary columns.
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

/// A LIKE filter demands side polys for exactly its bound column — not for
/// any other string column in the same table.
#[tokio::test]
async fn like_query_requires_exactly_its_column() {
    let cols = required_side_columns_for(
        r#"SELECT n_name FROM nation WHERE n_comment LIKE '%haggle%'"#,
        &["nation"],
    )
    .await;
    assert_eq!(cols, BTreeSet::from(["n_comment".to_string()]));
}

/// String equality goes through the hash column only — no side polys.
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

/// Build a bare `Like` IR node for `n_comment LIKE '<pattern>'`.
///
/// Goes through `Tree::from_expr` directly because the SQL pipeline never
/// hands a wildcard-only LIKE to the IR: the optimizer simplifies it away
/// before lowering.
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

/// A Like node with a real pattern declares its bound column.
#[test]
fn like_node_requires_its_column() {
    assert_eq!(
        like_tree("%haggle%").required_side_columns(),
        BTreeSet::from(["n_comment".to_string()])
    );
}

/// Wildcard-only patterns short-circuit to a constant and never touch side
/// segments, so they must not force side-column emission either.
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
