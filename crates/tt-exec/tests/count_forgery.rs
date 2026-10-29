#![cfg(feature = "test-utils")]
//! A dishonest prover against an ungrouped COUNT. The forgery adds one to
//! the count the prover's Aggregate outputs ([`set_count_forgery`]), and the
//! prover claims that count, so the result check passes and only COUNT's own
//! check can reject.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::path::Path;

use datafusion::arrow::{
    array::{Array, Int64Array},
    record_batch::RecordBatch,
};
use tt_core::test_utils::dishonest_prover::{set_claimed_result, set_count_forgery};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{
        read_result, resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread,
    },
};

const QUERY: &str = "SELECT COUNT(n_nationkey), SUM(n_nationkey) FROM nation";

async fn prove(pk: &Path, oracle: &Path, tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(QUERY.to_owned())
        .with_parquet_paths(vec![
            resolve_parquet_path("nation").expect("nation parquet"),
        ])
        .with_oracle_paths(vec![oracle.to_path_buf()])
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(
            workspace_artifacts_dir()
                .join(format!("count_forgery.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

/// `batch` with its first column, the count, plus one.
fn count_plus_one(batch: &RecordBatch) -> RecordBatch {
    let count = batch
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("COUNT is Int64");
    let forged = Int64Array::from_iter_values(count.values().iter().map(|c| c + 1));
    let mut columns = batch.columns().to_vec();
    columns[0] = std::sync::Arc::new(forged);
    RecordBatch::try_new(batch.schema(), columns).unwrap()
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn forged_ungrouped_count_is_rejected() {
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
    let claimed = count_plus_one(&read_result(&honest.result_path));

    let forged = {
        let _forgery = set_count_forgery(1);
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
        other => panic!("the forged count must fail a check, got {other:?}"),
    }
}
