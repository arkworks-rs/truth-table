#![cfg(feature = "test-utils")]
//! A dishonest prover against a cast that divides by `10^k`. The forgery
//! adds one to the cast's committed output ([`set_rescale_forgery`]), and
//! the prover claims that output, so the result check passes and only the
//! rescale's division check can reject.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::path::Path;

use datafusion::arrow::{
    array::{Array, Decimal128Array},
    record_batch::RecordBatch,
};
use tt_core::test_utils::dishonest_prover::{set_claimed_result, set_rescale_forgery};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{
        read_result, resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread,
    },
};

const QUERY: &str = "SELECT s_suppkey, CAST(s_acctbal AS DECIMAL(15, 1)) AS c FROM supplier";

async fn prove(pk: &Path, oracle: &Path, tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(QUERY.to_owned())
        .with_parquet_paths(vec![
            resolve_parquet_path("supplier").expect("supplier parquet"),
        ])
        .with_oracle_paths(vec![oracle.to_path_buf()])
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(
            workspace_artifacts_dir()
                .join(format!("cast_forgery.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

/// `batch` with one added to its second column, the cast (1.0 at scale 1).
fn cast_plus_one(batch: &RecordBatch) -> RecordBatch {
    let cast = batch
        .column(1)
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .expect("the cast is a decimal");
    let forged = Decimal128Array::from_iter_values(cast.values().iter().map(|c| c + 10))
        .with_data_type(cast.data_type().clone());
    let mut columns = batch.columns().to_vec();
    columns[1] = std::sync::Arc::new(forged);
    RecordBatch::try_new(batch.schema(), columns).unwrap()
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn forged_rescale_is_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let supplier = resolve_parquet_path("supplier").expect("supplier parquet");
    let oracle = resolve_oracle_path(&supplier, &pk)
        .await
        .expect("supplier oracle");

    let honest = prove(&pk, &oracle, "honest").await;
    verify_on_thread(
        QUERY,
        vec![oracle.clone()],
        &honest.proof_path,
        &honest.result_path,
        &vk,
    )
    .expect("the honest proof must verify; otherwise the rejection below proves nothing");
    let claimed = cast_plus_one(&read_result(&honest.result_path));

    let forged = {
        let _forgery = set_rescale_forgery();
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
        other => panic!("the forged rescale must fail a check, got {other:?}"),
    }
}
