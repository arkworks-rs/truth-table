#![cfg(feature = "test-utils")]
//! A dishonest prover claims NULL where the result is 0. The proof encodes
//! NULL as 0, so only the verifier's refusal of a NULL in the result keeps
//! the two apart.

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

const QUERY: &str = "SELECT COUNT(*) AS c FROM nation WHERE n_nationkey > 100";

#[tokio::test]
async fn a_null_claimed_for_zero_is_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let nation = resolve_parquet_path("nation").expect("nation parquet");
    let oracle = resolve_oracle_path(&nation, &pk)
        .await
        .expect("nation oracle");
    let artifact = |suffix: &str| {
        workspace_artifacts_dir().join(format!(
            "null_result_forgery.{}.{suffix}",
            std::process::id()
        ))
    };

    let honest = ProveBuilder::new()
        .with_query(QUERY.to_owned())
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
        QUERY,
        vec![oracle.clone()],
        &honest.proof_path,
        &honest.result_path,
        &vk,
    )
    .expect("the honest proof must verify; otherwise the rejection below proves nothing");

    let schema = Arc::new(Schema::new(vec![Field::new("c", DataType::Int64, true)]));
    let claimed = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int64Array::from(vec![None::<i64>]))],
    )
    .unwrap();
    let claimed_path = artifact("result.parquet");
    let mut writer = ArrowWriter::try_new(File::create(&claimed_path).unwrap(), schema, None)
        .expect("parquet writer");
    writer.write(&claimed).unwrap();
    writer.close().unwrap();

    let verdict = verify_on_thread(QUERY, vec![oracle], &honest.proof_path, &claimed_path, &vk);
    match verdict {
        Err(reason) if reason.contains("NULL is not supported") => {}
        other => panic!("a NULL in the result must be refused, got {other:?}"),
    }
}
