#![cfg(feature = "test-utils")]
//! A dishonest prover claims NULL where the result is a value, or a value
//! where it is NULL. The proof encodes NULL as 0, so the verifier keeps the
//! two apart itself: it computes a result fixed by a proved-empty input, and
//! refuses a NULL in any other.

use std::{fs::File, sync::Arc};

use datafusion::{
    arrow::{
        array::Int64Array,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    parquet::arrow::ArrowWriter,
};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::ProveBuilder,
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread},
};

/// Proves `query` over `nation` honestly, checks that the proof verifies,
/// then verifies it against `claimed` as the one-row result of column `name`.
async fn verify_claim(
    query: &str,
    name: &str,
    claimed: Option<i64>,
    tag: &str,
) -> Result<(), String> {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let nation = resolve_parquet_path("nation").expect("nation parquet");
    let oracle = resolve_oracle_path(&nation, &pk)
        .await
        .expect("nation oracle");
    let artifact = |suffix: &str| {
        workspace_artifacts_dir().join(format!(
            "null_result_forgery.{tag}.{}.{suffix}",
            std::process::id()
        ))
    };

    let honest = ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(vec![nation])
        .with_oracle_paths(vec![oracle.clone()])
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(artifact("pi")))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs");
    verify_on_thread(
        query,
        vec![oracle.clone()],
        &honest.proof_path,
        &honest.result_path,
        &vk,
    )
    .expect("the honest proof must verify; otherwise the rejection below proves nothing");

    let schema = Arc::new(Schema::new(vec![Field::new(name, DataType::Int64, true)]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int64Array::from(vec![claimed]))],
    )
    .unwrap();
    let claimed_path = artifact("result.parquet");
    let mut writer = ArrowWriter::try_new(File::create(&claimed_path).unwrap(), schema, None)
        .expect("parquet writer");
    writer.write(&batch).unwrap();
    writer.close().unwrap();

    verify_on_thread(query, vec![oracle], &honest.proof_path, &claimed_path, &vk)
}

const OVER_NO_ROWS: &str =
    "the claimed result is not the query's result over the proved-empty input";

#[tokio::test]
async fn a_null_claimed_for_a_count_of_zero_is_rejected() {
    let verdict = verify_claim(
        "SELECT COUNT(*) AS c FROM nation WHERE n_nationkey > 100",
        "c",
        None,
        "count",
    )
    .await;
    match verdict {
        Err(reason) if reason.contains(OVER_NO_ROWS) => {}
        other => panic!("a NULL claimed for COUNT 0 must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn a_zero_claimed_for_a_sum_over_no_rows_is_rejected() {
    let verdict = verify_claim(
        "SELECT SUM(n_nationkey) AS s FROM nation WHERE n_nationkey > 100",
        "s",
        Some(0),
        "empty_sum",
    )
    .await;
    match verdict {
        Err(reason) if reason.contains(OVER_NO_ROWS) => {}
        other => panic!("a 0 claimed for a SUM over no rows must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn a_null_claimed_for_a_sum_over_rows_is_rejected() {
    let verdict = verify_claim("SELECT SUM(n_nationkey) AS s FROM nation", "s", None, "sum").await;
    match verdict {
        Err(reason) if reason.contains("NULL is not supported") => {}
        other => panic!("a NULL claimed for a SUM over rows must be refused, got {other:?}"),
    }
}
