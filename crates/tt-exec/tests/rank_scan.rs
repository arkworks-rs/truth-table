#![cfg(feature = "test-utils")]
//! Table scans that load ranks no node reads ([`force_rank_columns`]): each
//! scan sets its ranks aside, so the nodes above it prove and verify as
//! without them, and a table committed without ranks is refused on both
//! sides with a clear error.
//!
//! The forced columns are process-wide, so these tests stay in their own
//! binary; every test forces the same set.

use tt_core::test_utils::forced_ranks::force_rank_columns;
use tt_exec::{
    commit::CommitBuilder,
    prove::ProveBuilder,
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{
        prove_and_verify_query, resolve_key_paths, resolve_oracle_path, resolve_parquet_path,
    },
    verify::VerifyBuilder,
};

const RANKED: [(&str, &str); 5] = [
    ("nation", "n_name"),
    ("nation", "n_comment"),
    ("region", "r_name"),
    ("region", "r_comment"),
    ("orders", "o_comment"),
];

/// A rank must not reach a filter, an equality fold, a group key, either
/// side of a join or a sort above its scan.
#[tokio::test]
async fn queries_over_ranked_scans_prove_and_verify() {
    force_rank_columns(&RANKED);
    for sql in [
        "SELECT n_name, n_regionkey FROM nation WHERE n_regionkey = 1",
        "SELECT n_nationkey FROM nation WHERE n_name = 'FRANCE'",
        "SELECT n_name, COUNT(*) FROM nation GROUP BY n_name",
        "SELECT n.n_name, r.r_name FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey",
        "SELECT n1.n_name AS left_name, n2.n_name AS right_name \
         FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey",
        "SELECT n1.n_nationkey, n2.n_regionkey FROM nation n1 JOIN nation n2 ON n1.n_name = n2.n_name",
        "SELECT n_name FROM nation ORDER BY n_name LIMIT 3",
        "SELECT n_name FROM nation WHERE n_comment LIKE '%haggle%'",
    ] {
        prove_and_verify_query(sql, &["nation", "region"], None)
            .await
            .unwrap_or_else(|err| panic!("{sql}: {err:#}"));
    }
}

/// `o_comment` (above the fingerprint `MIN_ROWS`) is pre-filtered, so its
/// scan carries fingerprint limbs, opened from the proof, beside the rank
/// from the oracle; both sides must order the two alike.
#[tokio::test]
async fn a_ranked_column_with_fingerprint_limbs_proves_and_verifies() {
    force_rank_columns(&RANKED);
    prove_and_verify_query(
        "SELECT o_orderkey FROM orders WHERE o_comment LIKE '%special%requests%'",
        &["orders"],
        None,
    )
    .await
    .expect("pre-filtered LIKE over a ranked column");
}

#[tokio::test]
async fn a_table_committed_without_ranks_is_refused() {
    force_rank_columns(&RANKED);
    let query = "SELECT n_name FROM nation";
    let expected = "table nation has no rank for column n_name";
    let dir = tempfile::tempdir().expect("temp dir");
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("test keys");
    let parquet = resolve_parquet_path("nation").expect("nation parquet");
    let rankless = CommitBuilder::new()
        .with_parquet_path(parquet.clone())
        .with_pk_path(pk.clone())
        .with_output_path(Some(dir.path().join("nation.oracle")))
        .with_ranks(false)
        .build()
        .expect("commit runner")
        .run()
        .await
        .expect("commit without ranks");
    let prove = |oracle, name: &str| {
        ProveBuilder::new()
            .with_query(query.to_owned())
            .with_parquet_path(parquet.clone())
            .with_oracle_path(oracle)
            .with_pk_path(pk.clone())
            .with_output_path(Some(dir.path().join(name)))
            .build()
            .expect("prove runner")
    };

    let Err(refused) = prove(rankless.clone(), "refused.pi").run().await else {
        panic!("the prover needs the committed rank");
    };
    assert!(format!("{refused:#}").contains(expected), "{refused:#}");

    let ranked = resolve_oracle_path(&parquet, &pk)
        .await
        .expect("committed oracle");
    let outputs = prove(ranked, "honest.pi")
        .run()
        .await
        .expect("prove with ranks");
    let refused = VerifyBuilder::new()
        .with_query(query.to_owned())
        .with_oracle_path(rankless)
        .with_proof_path(outputs.proof_path)
        .with_result_path(outputs.result_path)
        .with_vk_path(vk)
        .build()
        .expect("verify runner")
        .run()
        .await
        .expect_err("the verifier needs the committed rank");
    assert!(format!("{refused:#}").contains(expected), "{refused:#}");
}
