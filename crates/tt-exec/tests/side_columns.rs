#![cfg(feature = "test-utils")]

//! `Tree::required_side_columns` decides which string columns' side polys
//! (`__chars`, `__orig_ind`, `__int_ind`, `__bnd`) a query encodes and
//! tracks; the data owner commits them for every string column, or for none.
//! It must name exactly the columns consumed by white-box string gadgets
//! (LIKE), so a query without one loads no auxiliary column (paper: "Dropping
//! Auxiliary Columns"), and a table committed without them serves every
//! query but LIKE.

use std::collections::BTreeSet;

use datafusion::prelude::{ParquetReadOptions, SessionContext};
use front_end::shared::TTSharedConfig;
use tt_core::irs::shared_ir::EmptyIr;
use tt_exec::backend::BenchBackend;
use tt_exec::{
    prove::ProveBuilder,
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{StringCommit, resolve_key_paths, resolve_oracle_path_for, resolve_parquet_path},
    verify::VerifyBuilder,
};

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

/// The `_tt` and `_pgn` queries of the benchmark suite are LIKE-free, so
/// none may load auxiliary columns; a `_tt_2` query loads them for its LIKE
/// column only, if it has one.
#[tokio::test]
async fn tpch_bench_queries_require_side_columns_for_like_only() {
    use tpch_data::Variant;
    // Mirrors the cases in benches/tpch/mod.rs.
    let tt_queries: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 17, 18, 19, 20];
    let pgn_queries: &[u8] = &[1, 3, 5, 8, 9, 18];
    for &(numbers, variant) in &[(tt_queries, Variant::Tt), (pgn_queries, Variant::Pgn)] {
        for &number in numbers {
            let spec = tpch_data::query_spec(number, variant);
            let cols = required_side_columns_for(spec.sql, spec.tables).await;
            assert!(
                cols.is_empty(),
                "TPC-H q{number} ({variant:?}) has no LIKE but would load side columns {cols:?}"
            );
        }
    }
    for number in tpch_data::TT_2_QUERIES {
        let like = match number {
            2 | 14 => Some("p_type"),
            9 | 20 => Some("p_name"),
            _ => None,
        };
        let spec = tpch_data::query_spec(number, Variant::Tt2);
        let cols = required_side_columns_for(spec.sql, spec.tables).await;
        assert_eq!(
            cols,
            like.into_iter().map(String::from).collect::<BTreeSet<_>>(),
            "TPC-H q{number}_tt_2"
        );
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

/// A table committed without side columns proves and verifies a query with
/// no LIKE, and both sides refuse a LIKE over it with a clear error.
#[tokio::test]
async fn a_table_committed_without_side_columns_refuses_like() {
    let like = "SELECT n_nationkey FROM nation WHERE n_comment LIKE '%haggle%'";
    let expected = "table nation has no side columns for column n_comment";
    tt_exec::test_utils::prove_and_verify_query_with(
        "SELECT n_nationkey FROM nation WHERE n_name = 'FRANCE'",
        &["nation"],
        None,
        StringCommit::HashOnly,
    )
    .await
    .expect("a query with no LIKE over the hash-only table");

    let dir = tempfile::tempdir().expect("temp dir");
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("test keys");
    let parquet = resolve_parquet_path("nation").expect("nation parquet");
    let prove = |oracle, name: &str| {
        ProveBuilder::new()
            .with_query(like.to_owned())
            .with_parquet_path(parquet.clone())
            .with_oracle_path(oracle)
            .with_pk_path(pk.clone())
            .with_output_path(Some(dir.path().join(name)))
            .build()
            .expect("prove runner")
    };
    let hash_only = resolve_oracle_path_for(&parquet, &pk, StringCommit::HashOnly)
        .await
        .expect("hash-only oracle");

    let Err(refused) = prove(hash_only.clone(), "refused.pi").run().await else {
        panic!("the prover needs the committed side columns");
    };
    assert!(format!("{refused:#}").contains(expected), "{refused:#}");

    let white_box = resolve_oracle_path_for(&parquet, &pk, StringCommit::WhiteBox)
        .await
        .expect("white-box oracle");
    let outputs = prove(white_box, "honest.pi")
        .run()
        .await
        .expect("prove with side columns");
    let refused = VerifyBuilder::new()
        .with_query(like.to_owned())
        .with_oracle_path(hash_only)
        .with_proof_path(outputs.proof_path)
        .with_result_path(outputs.result_path)
        .with_vk_path(vk)
        .build()
        .expect("verify runner")
        .run()
        .await
        .expect_err("the verifier needs the committed side columns");
    assert!(format!("{refused:#}").contains(expected), "{refused:#}");
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
