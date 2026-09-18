//! Self-contained end-to-end regressions for proved ORDER BY output keys.

use std::{fs::File, path::Path, sync::Arc};

use anyhow::Result;
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, Int64Array},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::parquet::arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder};
use tt_exec::{
    commit::CommitBuilder, prove::ProveBuilder, setup::SetupBuilder, verify::VerifyBuilder,
};

fn write_batch(path: &Path, batch: &RecordBatch) -> Result<()> {
    let mut writer = ArrowWriter::try_new(File::create(path)?, batch.schema(), None)?;
    writer.write(batch)?;
    writer.close()?;
    Ok(())
}

fn input_table() -> Result<RecordBatch> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("group_id", DataType::Int64, false),
        Field::new("value", DataType::Int64, false),
        Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
        Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
    ]));
    Ok(RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int64Array::from(vec![1, 1, 2, 2])) as ArrayRef,
            Arc::new(Int64Array::from(vec![30, 10, 40, 20])) as ArrayRef,
            Arc::new(Int64Array::from(vec![0, 1, 2, 3])) as ArrayRef,
            Arc::new(BooleanArray::from(vec![true; 4])) as ArrayRef,
        ],
    )?)
}

fn parquet_rows(path: &Path) -> Result<Vec<(i64, i64)>> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?.build()?;
    let mut rows = Vec::new();
    for batch in reader {
        let batch = batch?;
        let groups = batch
            .column_by_name("group_id")
            .expect("query result should contain group_id")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("group_id should remain Int64");
        let values = batch
            .column_by_name("value")
            .expect("query result should contain value")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("value should remain Int64");
        rows.extend(
            groups
                .values()
                .iter()
                .copied()
                .zip(values.values().iter().copied()),
        );
    }
    Ok(rows)
}

async fn prove_and_verify(query: &str, suffix: &str) -> Result<Vec<(i64, i64)>> {
    let dir = tempfile::tempdir()?;
    let table_path = dir.path().join("order_input.parquet");
    let pk_path = dir.path().join("order.pk");
    let vk_path = dir.path().join("order.vk");
    write_batch(&table_path, &input_table()?)?;
    let parquet_schema = ParquetRecordBatchReaderBuilder::try_new(File::open(&table_path)?)?
        .schema()
        .clone();
    assert!(
        !parquet_schema.field_with_name("value")?.is_nullable(),
        "the source Parquet schema should preserve its required column"
    );

    SetupBuilder::new()
        .with_size_label(Some("16".to_owned()))
        .with_pk_path(Some(pk_path.clone()))
        .with_vk_path(Some(vk_path.clone()))
        .build()?
        .run()?;
    let oracle = CommitBuilder::new()
        .with_parquet_path(table_path.clone())
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(dir.path().join("order.oracle")))
        .build()?
        .run()
        .await?;
    let output = ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(vec![table_path])
        .with_oracle_paths(vec![oracle.clone()])
        .with_pk_path(pk_path)
        .with_output_path(Some(dir.path().join(format!("order-{suffix}.proof"))))
        .build()?
        .run()
        .await?;
    let rows = parquet_rows(&output.result_path)?;

    VerifyBuilder::new()
        .with_query(query.to_owned())
        .with_oracle_paths(vec![oracle])
        .with_proof_path(output.proof_path)
        .with_result_path(output.result_path)
        .with_vk_path(vk_path)
        .build()?
        .run()
        .await?;
    Ok(rows)
}

#[tokio::test]
async fn ascending_order_by_proves_the_actual_output_order() -> Result<()> {
    let rows = prove_and_verify(
        "SELECT group_id, value FROM order_input ORDER BY value ASC",
        "ascending",
    )
    .await?;
    assert_eq!(rows, vec![(1, 10), (2, 20), (1, 30), (2, 40)]);
    Ok(())
}

#[tokio::test]
async fn mixed_direction_multicolumn_order_is_proved() -> Result<()> {
    let rows = prove_and_verify(
        "SELECT group_id, value FROM order_input ORDER BY group_id ASC, value DESC",
        "mixed-keys",
    )
    .await?;
    assert_eq!(rows, vec![(1, 30), (1, 10), (2, 40), (2, 20)]);
    Ok(())
}
