#![cfg(feature = "test-utils")]
//! Proofs without the data-dependent rules, so nothing is compacted: every
//! operator reads its input on the input's own domain.

use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::ProveBuilder,
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread},
};

async fn prove_and_verify_without_compaction(query: &str, tag: &str) {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let nation = resolve_parquet_path("nation").expect("nation parquet");
    let oracle = resolve_oracle_path(&nation, &pk)
        .await
        .expect("nation oracle");
    let outputs = ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(vec![nation])
        .with_oracle_paths(vec![oracle.clone()])
        .with_pk_path(pk.to_path_buf())
        .with_data_dependent_rules(Vec::new())
        .with_output_path(Some(
            workspace_artifacts_dir()
                .join(format!("no_compaction.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs");
    verify_on_thread(
        query,
        vec![oracle],
        &outputs.proof_path,
        &outputs.result_path,
        &vk,
    )
    .expect("the proof verifies");
}

/// HAVING filters on the uncompacted aggregate's activator, which only marks
/// the group representatives.
#[tokio::test]
async fn having() {
    prove_and_verify_without_compaction(
        "SELECT n_regionkey FROM nation GROUP BY n_regionkey HAVING max(n_nationkey) > 22",
        "having",
    )
    .await;
}

/// The join reads its right side's keys under the HAVING filter's
/// activator, as in TPC-H Q18.
#[tokio::test]
async fn join_with_a_having_subquery() {
    prove_and_verify_without_compaction(
        "SELECT n_name FROM nation, \
         (SELECT n_regionkey AS big_region FROM nation GROUP BY n_regionkey \
          HAVING max(n_nationkey) > 22) AS big \
         WHERE n_regionkey = big_region",
        "having_join",
    )
    .await;
}
