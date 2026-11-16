#![cfg(feature = "test-utils")]
//! A dishonest prover marks the filter under a SUM as proved empty and
//! claims the NULL a SUM over no rows yields. The verifier computes that
//! same NULL, so only the zerocheck on the filter's activator can reject.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use datafusion::arrow::{array::new_null_array, record_batch::RecordBatch};
use tt_core::test_utils::dishonest_prover::{set_claimed_result, set_empty_first_filter};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread},
};

const QUERY: &str = "SELECT SUM(n_nationkey) AS s FROM nation WHERE n_nationkey < 4";

async fn prove(pk: &Path, oracle: &Path, tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(QUERY.to_owned())
        .with_parquet_paths(vec![resolve_parquet_path("nation").expect("test parquet")])
        .with_oracle_paths(vec![oracle.to_path_buf()])
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(workspace_artifacts_dir().join(format!(
            "empty_aggregate_input_forgery.{tag}.{}.pi",
            std::process::id()
        ))))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn a_null_sum_over_a_filter_claimed_empty_is_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let parquet = resolve_parquet_path("nation").expect("test parquet");
    let oracle: PathBuf = resolve_oracle_path(&parquet, &pk)
        .await
        .expect("test oracle");

    let honest = prove(&pk, &oracle, "honest").await;
    verify_on_thread(
        QUERY,
        vec![oracle.clone()],
        &honest.proof_path,
        &honest.result_path,
        &vk,
    )
    .expect("the honest proof must verify; otherwise the rejection below proves nothing");

    let forged = {
        let _forgery = set_empty_first_filter();
        let _claimed = set_claimed_result(Box::new(|batches: Vec<RecordBatch>| {
            batches
                .iter()
                .map(|batch| {
                    let columns = batch
                        .columns()
                        .iter()
                        .map(|column| new_null_array(column.data_type(), batch.num_rows()))
                        .collect();
                    RecordBatch::try_new(Arc::clone(&batch.schema()), columns)
                        .expect("a NULL result")
                })
                .collect()
        }));
        prove(&pk, &oracle, "forged").await
    };
    match verify_on_thread(
        QUERY,
        vec![oracle],
        &forged.proof_path,
        &forged.result_path,
        &vk,
    ) {
        Ok(()) => panic!("a NULL SUM over a non-empty filter claimed empty verified"),
        Err(reason) => assert!(
            reason.contains("verifier cryptographic verification failed")
                && !reason.contains("panicked"),
            "rejected for another reason: {reason}"
        ),
    }
}
