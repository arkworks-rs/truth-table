//! Security regression: an honest proof must reject modified public results.
//!
//! This uses the production setup/commit/prove/verify entry points, not a
//! hand-built verifier or a malicious prover. Every adversarial mutation reuses
//! the identical serialized proof and input commitment; only the claimed result
//! file changes.
//! Public NULLs are rejected explicitly because the current field encoding
//! does not authenticate Arrow validity bits. This regression exercises
//! field-encoding equality on a NULL-free query pipeline; general SQL NULL
//! semantics remain unsupported until internal validity columns are proved.

use std::{fs::File, path::Path, sync::Arc};

use anyhow::{Context, Result};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, Int64Array, UInt32Array, UInt64Array},
    compute::{concat_batches, take},
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

fn read_batch(path: &Path) -> Result<RecordBatch> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?.build()?;
    let batches = reader.collect::<std::result::Result<Vec<_>, _>>()?;
    let schema = batches
        .first()
        .context("expected a nonempty result")?
        .schema();
    Ok(concat_batches(&schema, &batches)?)
}

fn read_row_count(path: &Path) -> Result<usize> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?.build()?;
    Ok(reader
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .map(RecordBatch::num_rows)
        .sum())
}

async fn verify_result(
    query: &str,
    oracle_path: &Path,
    proof_path: &Path,
    result_path: &Path,
    vk_path: &Path,
) -> Result<()> {
    VerifyBuilder::new()
        .with_query(query.to_owned())
        .with_oracle_path(oracle_path.to_path_buf())
        .with_proof_path(proof_path.to_path_buf())
        .with_result_path(result_path.to_path_buf())
        .with_vk_path(vk_path.to_path_buf())
        .build()?
        .run()
        .await
}

#[tokio::test]
async fn fixed_proof_rejects_reordered_and_changed_public_rows() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let input_path = dir.path().join("audit_input.parquet");
    let pk_path = dir.path().join("audit.pk");
    let vk_path = dir.path().join("audit.vk");
    let proof_path = dir.path().join("honest.proof");

    let schema = Arc::new(Schema::new(vec![
        // Keep the visible result nullable so the NULL-substitution regression
        // exercises cell validity rather than merely a schema mismatch.
        Field::new("value", DataType::Int64, true),
        Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
        Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
    ]));
    let input = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int64Array::from(vec![Some(4), Some(1), Some(0), Some(2)])) as ArrayRef,
            Arc::new(Int64Array::from(vec![0, 1, 2, 3])) as ArrayRef,
            Arc::new(BooleanArray::from(vec![true; 4])) as ArrayRef,
        ],
    )?;
    write_batch(&input_path, &input)?;

    // Small setup for four rows, with room for the sort/range and public-result
    // fingerprint auxiliaries.  The latter reaches a 15-variable polynomial.
    SetupBuilder::new()
        .with_size_label(Some("16".to_owned()))
        .with_pk_path(Some(pk_path.clone()))
        .with_vk_path(Some(vk_path.clone()))
        .build()?
        .run()?;
    let oracle_path = CommitBuilder::new()
        .with_parquet_path(input_path.clone())
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(dir.path().join("audit_input.oracle")))
        .build()?
        .run()
        .await?;

    let query = "SELECT value FROM audit_input ORDER BY value ASC";
    let output = ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_path(input_path.clone())
        .with_oracle_path(oracle_path.clone())
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(proof_path))
        .build()?
        .run()
        .await
        .context("honest proving must succeed before assessing result binding")?;

    let honest = read_batch(&output.result_path)?;
    assert_eq!(honest.num_columns(), 1);
    let values = honest
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .context("expected Int64 query output")?;
    assert_eq!(values.values().as_ref(), &[0, 1, 2, 4]);
    verify_result(
        query,
        &oracle_path,
        &output.proof_path,
        &output.result_path,
        &vk_path,
    )
    .await
    .context("honest verification must succeed before assessing result binding")?;
    eprintln!("public-result binding: honest result accepted");

    // Preserve the complete Arrow schema and all row values; change only order.
    // This must fail because this *same proof* is transcript-bound to the exact
    // public encoding, not because the underlying ResultCheck relation is
    // ordered. The tt-core regression separately confirms that a fresh proof
    // may certify this reordered bag.
    let reverse_indices = UInt32Array::from(vec![3, 2, 1, 0]);
    let reversed_columns = honest
        .columns()
        .iter()
        .map(|column| take(column.as_ref(), &reverse_indices, None))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let reversed = RecordBatch::try_new(honest.schema(), reversed_columns)?;
    let reversed_path = dir.path().join("reversed.parquet");
    write_batch(&reversed_path, &reversed)?;
    let reversed_result = verify_result(
        query,
        &oracle_path,
        &output.proof_path,
        &reversed_path,
        &vk_path,
    )
    .await;
    eprintln!("public-result binding: reversed rows = {reversed_result:?}");

    // Preserve order, row count, field type, and schema; change one actual value.
    let changed = RecordBatch::try_new(
        honest.schema(),
        vec![Arc::new(Int64Array::from(vec![Some(0), Some(1), Some(2), Some(5)])) as ArrayRef],
    )?;
    let changed_path = dir.path().join("changed.parquet");
    write_batch(&changed_path, &changed)?;
    let changed_result = verify_result(
        query,
        &oracle_path,
        &output.proof_path,
        &changed_path,
        &vk_path,
    )
    .await;
    eprintln!("public-result binding: changed value = {changed_result:?}");

    // NULL and integer zero currently have the same field encoding. Keep the
    // exact nullable schema and replace only the public zero with NULL; the
    // public-result boundary must reject this until validity columns are
    // included in the authenticated relation.
    let null_substitution = RecordBatch::try_new(
        honest.schema(),
        vec![Arc::new(Int64Array::from(vec![None, Some(1), Some(2), Some(4)])) as ArrayRef],
    )?;
    let null_path = dir.path().join("null-substitution.parquet");
    write_batch(&null_path, &null_substitution)?;
    let null_result = verify_result(
        query,
        &oracle_path,
        &output.proof_path,
        &null_path,
        &vk_path,
    )
    .await;
    eprintln!("public-result binding: NULL substitution = {null_result:?}");

    // Preserve the positive numeric values but change their SQL/Arrow type.
    // The field encodings coincide for these values, so rejecting this file
    // specifically exercises the typed public-schema check.
    let wrong_type_schema = Arc::new(Schema::new(vec![Field::new(
        "value",
        DataType::UInt64,
        true,
    )]));
    let wrong_type = RecordBatch::try_new(
        wrong_type_schema,
        vec![Arc::new(UInt64Array::from(vec![0, 1, 2, 4])) as ArrayRef],
    )?;
    let wrong_type_path = dir.path().join("wrong-type.parquet");
    write_batch(&wrong_type_path, &wrong_type)?;
    let wrong_type_result = verify_result(
        query,
        &oracle_path,
        &output.proof_path,
        &wrong_type_path,
        &vk_path,
    )
    .await;
    eprintln!("public-result binding: wrong type = {wrong_type_result:?}");

    assert!(
        reversed_result.is_err()
            && changed_result.is_err()
            && null_result.is_err()
            && wrong_type_result.is_err(),
        "an honest proof must reject every tampered result; reversed rows: \
        {reversed_result:?}; changed value: {changed_result:?}; NULL substitution: \
         {null_result:?}; wrong type: {wrong_type_result:?}"
    );

    // Exercise verifier-local public oracles whose evaluations are constant.
    // They are verifier-owned base oracles, not proof-owned constants, and must
    // remain valid inputs to ResultCheck.
    // Keep a source-column dependency so this regression exercises ResultCheck
    // rather than the separate constant-only TableScan projection limitation.
    let constant_query = "SELECT value - value + 7 AS value FROM audit_input";
    let constant_output = ProveBuilder::new()
        .with_query(constant_query.to_owned())
        .with_parquet_path(input_path.clone())
        .with_oracle_path(oracle_path.clone())
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(dir.path().join("constant.proof")))
        .build()?
        .run()
        .await
        .context("proving a constant-valued public result must succeed")?;
    verify_result(
        constant_query,
        &oracle_path,
        &constant_output.proof_path,
        &constant_output.result_path,
        &vk_path,
    )
    .await
    .context("a constant-valued public result must verify")?;
    eprintln!("public-result binding: honest constant result accepted");

    // Exercise the production normalization and verifier tracking path for a
    // genuinely empty result. ResultCheck handles the all-zero activator
    // without treating its verifier-local constant columns as proof input.
    let empty_query = "SELECT value FROM audit_input WHERE value = 99";
    let empty_output = ProveBuilder::new()
        .with_query(empty_query.to_owned())
        .with_parquet_path(input_path.clone())
        .with_oracle_path(oracle_path.clone())
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(dir.path().join("empty.proof")))
        .build()?
        .run()
        .await
        .context("proving an empty public result must succeed")?;
    assert_eq!(read_row_count(&empty_output.result_path)?, 0);
    verify_result(
        empty_query,
        &oracle_path,
        &empty_output.proof_path,
        &empty_output.result_path,
        &vk_path,
    )
    .await
    .context("an empty public result must verify")?;
    eprintln!("public-result binding: honest empty result accepted");

    // Only the terminal query result has a verifier-supplied OUTPUT table.
    // An IN subquery is an internal computation and must not receive its own
    // nested ResultCheck, which would otherwise fail for lack of a second
    // public payload during production verification.
    let subquery = "SELECT value FROM audit_input \
        WHERE value IN (SELECT value FROM audit_input WHERE value <= 1) \
        ORDER BY value ASC";
    let subquery_output = ProveBuilder::new()
        .with_query(subquery.to_owned())
        .with_parquet_path(input_path)
        .with_oracle_path(oracle_path.clone())
        .with_pk_path(pk_path)
        .with_output_path(Some(dir.path().join("subquery.proof")))
        .build()?
        .run()
        .await
        .context("proving a query with an internal subquery must succeed")?;
    let subquery_result = read_batch(&subquery_output.result_path)?;
    let subquery_values = subquery_result
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .context("expected Int64 subquery output")?;
    assert_eq!(subquery_values.values().as_ref(), &[0, 1]);
    verify_result(
        subquery,
        &oracle_path,
        &subquery_output.proof_path,
        &subquery_output.result_path,
        &vk_path,
    )
    .await
    .context("only the terminal ResultCheck should bind a subquery result")?;
    eprintln!("public-result binding: honest IN-subquery result accepted");
    Ok(())
}
