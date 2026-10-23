#![cfg(feature = "test-utils")]
//! The proof encodes NULL as 0, so NULL is kept out: the data owner does not
//! commit one in an active row, and a query cannot produce one.

use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::arrow::array::{BooleanArray, Int64Array};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::parquet::arrow::ArrowWriter;
use tt_exec::commit::CommitBuilder;
use tt_exec::setup::DEFAULT_TEST_LOG_SIZE;
use tt_exec::test_utils::{prove_and_verify_query, resolve_key_paths};

#[tokio::test]
async fn a_null_in_an_active_row_is_not_committed() {
    let dir = tempfile::tempdir().unwrap();
    let parquet_path = dir.path().join("with_null.parquet");
    let schema = Arc::new(Schema::new(vec![
        Field::new("k", DataType::Int64, true),
        Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
        Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![Some(1), None])),
            Arc::new(Int64Array::from(vec![0, 1])),
            Arc::new(BooleanArray::from(vec![true, true])),
        ],
    )
    .unwrap();
    let mut writer =
        ArrowWriter::try_new(std::fs::File::create(&parquet_path).unwrap(), schema, None).unwrap();
    writer.write(&batch).unwrap();
    writer.close().unwrap();

    let (pk_path, _) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).unwrap();
    let result = CommitBuilder::new()
        .with_parquet_path(parquet_path)
        .with_pk_path(pk_path)
        .with_output_path(Some(dir.path().to_path_buf()))
        .build()
        .unwrap()
        .run()
        .await;
    let error = format!("{:#}", result.expect_err("a NULL must not be committed"));
    assert!(error.contains("NULL is not supported"), "{error}");
}

#[tokio::test]
#[should_panic(expected = "NULL is not supported")]
async fn a_null_literal_is_not_supported() {
    let _ = prove_and_verify_query(
        "SELECT n_name, CAST(NULL AS BIGINT) AS missing FROM nation",
        &["nation"],
        None,
    )
    .await;
}

#[tokio::test]
#[should_panic(expected = "NULL is not supported")]
async fn case_without_else_is_not_supported() {
    let _ = prove_and_verify_query(
        "SELECT CASE WHEN n_nationkey < 5 THEN n_regionkey END AS k FROM nation",
        &["nation"],
        None,
    )
    .await;
}
