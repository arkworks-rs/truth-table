//! End-to-end regression for LIMIT's virtual output and committed metadata.

use std::{fs::File, path::Path, sync::Arc};

use anyhow::Result;
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, Int64Array},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::parquet::arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder};
use front_end::structs::{Artifact, TTProof};
use tt_exec::{
    backend::BenchBackend, commit::CommitBuilder, prove::ProveBuilder, setup::SetupBuilder,
    verify::VerifyBuilder,
};

type F = <BenchBackend as SnarkBackend>::F;

fn write_batch(path: &Path, batch: &RecordBatch) -> Result<()> {
    let mut writer = ArrowWriter::try_new(File::create(path)?, batch.schema(), None)?;
    writer.write(batch)?;
    writer.close()?;
    Ok(())
}

fn input_table() -> Result<RecordBatch> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("value", DataType::Int64, false),
        Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
        Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
    ]));
    Ok(RecordBatch::try_new(
        schema,
        vec![
            Arc::new(Int64Array::from(vec![10, 20, 30, 40])) as ArrayRef,
            Arc::new(Int64Array::from(vec![0, 1, 2, 3])) as ArrayRef,
            Arc::new(BooleanArray::from(vec![true; 4])) as ArrayRef,
        ],
    )?)
}

fn parquet_row_count(path: &Path) -> Result<usize> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?.build()?;
    Ok(reader
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .map(RecordBatch::num_rows)
        .sum())
}

#[tokio::test]
async fn virtual_limit_output_proves_and_verifies() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let table_path = dir.path().join("limit_input.parquet");
    let pk_path = dir.path().join("limit.pk");
    let vk_path = dir.path().join("limit.vk");
    write_batch(&table_path, &input_table()?)?;

    SetupBuilder::new()
        .with_size_label(Some("16".to_owned()))
        .with_pk_path(Some(pk_path.clone()))
        .with_vk_path(Some(vk_path.clone()))
        .build()?
        .run()?;
    let oracle = CommitBuilder::new()
        .with_parquet_path(table_path.clone())
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(dir.path().join("limit.oracle")))
        .build()?
        .run()
        .await?;

    let query = "SELECT value FROM limit_input LIMIT 2";
    let output = ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(vec![table_path.clone()])
        .with_oracle_paths(vec![oracle.clone()])
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(dir.path().join("limit.proof")))
        .build()?
        .run()
        .await?;
    assert_eq!(parquet_row_count(&output.result_path)?, 2);

    // The plan-level prefix endpoint and gadget-level output count are both
    // proof-owned constants, not unbound miscellaneous metadata. They happen
    // to equal two for this dense input, so the deduplicated value has at
    // least two tracker IDs referring to it.
    let proof = TTProof::<BenchBackend>::load(&output.proof_path)?;
    let snark = proof.as_snark_proof();
    let two_constant_id = snark
        .mv_pcs_subproof
        .unique_constants
        .iter()
        .find_map(|(id, value)| (*value == F::from(2u64)).then_some(*id))
        .expect("LIMIT prefix/count constants should be present");
    assert!(
        snark
            .mv_pcs_subproof
            .constant_map
            .values()
            .filter(|id| **id == two_constant_id)
            .count()
            >= 2
    );
    assert!(
        snark
            .miscellaneous_field_elements
            .keys()
            .all(|key| !key.starts_with("limit_"))
    );

    VerifyBuilder::new()
        .with_query(query.to_owned())
        .with_oracle_paths(vec![oracle.clone()])
        .with_proof_path(output.proof_path)
        .with_result_path(output.result_path)
        .with_vk_path(vk_path.clone())
        .build()?
        .run()
        .await?;

    // Repeated LIMIT nodes exercise sequential committed-prefix/count values
    // across independently reconstructed prover and verifier IR trees.
    let nested_query = "SELECT value FROM (SELECT value FROM limit_input LIMIT 3) bounded LIMIT 2";
    let nested = ProveBuilder::new()
        .with_query(nested_query.to_owned())
        .with_parquet_paths(vec![table_path])
        .with_oracle_paths(vec![oracle.clone()])
        .with_pk_path(pk_path)
        .with_output_path(Some(dir.path().join("nested-limit.proof")))
        .build()?
        .run()
        .await?;
    assert_eq!(parquet_row_count(&nested.result_path)?, 2);

    VerifyBuilder::new()
        .with_query(nested_query.to_owned())
        .with_oracle_paths(vec![oracle])
        .with_proof_path(nested.proof_path)
        .with_result_path(nested.result_path)
        .with_vk_path(vk_path)
        .build()?
        .run()
        .await
}
