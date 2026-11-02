#![cfg(feature = "test-utils")]
//! A dishonest prover against an aggregate without GROUP BY. The forgery
//! splits the SUM over two active output rows, `S − 1` and `1`
//! ([`set_split_ungrouped_forgery`]), and the prover claims those two rows.
//! Their activator-weighted total is the honest sum, so only the aggregate's
//! single output row can reject them.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::{path::Path, sync::Arc};

use datafusion::arrow::{
    array::{Array, Int64Array},
    record_batch::RecordBatch,
};
use tt_core::test_utils::dishonest_prover::{set_claimed_result, set_split_ungrouped_forgery};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{
        read_result, resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread,
    },
};

const QUERY: &str = "SELECT SUM(n_nationkey) AS s FROM nation";

async fn prove(pk: &Path, oracle: &Path, tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(QUERY.to_owned())
        .with_parquet_paths(vec![
            resolve_parquet_path("nation").expect("nation parquet"),
        ])
        .with_oracle_paths(vec![oracle.to_path_buf()])
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(workspace_artifacts_dir().join(format!(
            "ungrouped_aggregate_forgery.{tag}.{}.pi",
            std::process::id()
        ))))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

/// The one-row result `batch`, split into the rows `S − 1` and `1`.
fn split(batch: &RecordBatch) -> RecordBatch {
    let sum = batch
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("SUM is Int64");
    assert_eq!(sum.len(), 1, "an ungrouped SUM has one row");
    let split = Int64Array::from(vec![sum.value(0) - 1, 1]);
    RecordBatch::try_new(batch.schema(), vec![Arc::new(split)]).unwrap()
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn a_split_ungrouped_sum_is_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let nation = resolve_parquet_path("nation").expect("nation parquet");
    let oracle = resolve_oracle_path(&nation, &pk)
        .await
        .expect("nation oracle");

    let honest = prove(&pk, &oracle, "honest").await;
    verify_on_thread(
        QUERY,
        vec![oracle.clone()],
        &honest.proof_path,
        &honest.result_path,
        &vk,
    )
    .expect("the honest proof must verify; otherwise the rejection below proves nothing");
    let claimed = split(&read_result(&honest.result_path));

    let forged = {
        let _forgery = set_split_ungrouped_forgery();
        let _claimed = set_claimed_result(Box::new(move |_| vec![claimed.clone()]));
        prove(&pk, &oracle, "forged").await
    };
    let verdict = verify_on_thread(
        QUERY,
        vec![oracle.clone()],
        &forged.proof_path,
        &forged.result_path,
        &vk,
    );
    match verdict {
        Err(reason)
            if reason.contains("verifier cryptographic verification failed")
                && !reason.contains("panicked") => {}
        other => panic!("the split SUM must fail a check, got {other:?}"),
    }
}
