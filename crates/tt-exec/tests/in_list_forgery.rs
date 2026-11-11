#![cfg(feature = "test-utils")]
//! A dishonest prover against a string IN list. The forgery commits the
//! negated membership result ([`set_in_list_forgery`]), and the prover claims
//! that result, so the result check passes and only the membership gadget can
//! reject.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::{path::Path, sync::Arc};

use datafusion::arrow::{
    array::{Array, BooleanArray},
    compute::not,
    record_batch::RecordBatch,
};
use tt_core::test_utils::dishonest_prover::{set_claimed_result, set_in_list_forgery};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{
        read_result, resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread,
    },
};

const QUERY: &str = "SELECT n_nationkey, n_name IN ('ALGERIA', 'BRAZIL', 'CANADA', 'EGYPT') AS c \
     FROM nation";

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
                .join(format!("in_list_forgery.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

/// `batch` with its second column, the membership flag, negated.
fn flag_negated(batch: &RecordBatch) -> RecordBatch {
    let flag = batch
        .column(1)
        .as_any()
        .downcast_ref::<BooleanArray>()
        .expect("the flag is a boolean");
    assert!(
        flag.true_count() > 0 && flag.false_count() > 0,
        "the honest flag should hold both values"
    );
    let mut columns = batch.columns().to_vec();
    columns[1] = Arc::new(not(flag).unwrap());
    RecordBatch::try_new(batch.schema(), columns).unwrap()
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn forged_in_list_is_rejected() {
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
    let claimed = flag_negated(&read_result(&honest.result_path));

    let forged = {
        let _forgery = set_in_list_forgery();
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
        other => panic!("the forged IN list must fail a check, got {other:?}"),
    }
}
