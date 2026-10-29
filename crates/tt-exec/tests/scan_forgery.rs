#![cfg(feature = "test-utils")]
//! A dishonest prover that commits the scanned table itself
//! ([`set_unowned_scans`]) instead of loading the data owner's oracle. A
//! `COUNT(*)` scan reads no column, so nothing in its schema names the
//! table: the verifier must still find the table's oracle, or the prover
//! would choose the rows, and so the count.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::path::Path;

use tt_core::test_utils::dishonest_prover::set_unowned_scans;
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread},
};

const QUERY: &str = "SELECT COUNT(*) FROM nation";

async fn prove(pk: &Path, oracle: &Path, tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(QUERY.to_owned())
        .with_parquet_paths(vec![
            resolve_parquet_path("nation").expect("nation parquet"),
        ])
        .with_oracle_paths(vec![oracle.to_path_buf()])
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(
            workspace_artifacts_dir().join(format!("scan_forgery.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

#[tokio::test]
async fn a_scan_the_prover_commits_is_rejected() {
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

    let forged = {
        let _forgery = set_unowned_scans();
        prove(&pk, &oracle, "forged").await
    };
    let reason = verify_on_thread(
        QUERY,
        vec![oracle.clone()],
        &forged.proof_path,
        &forged.result_path,
        &vk,
    )
    .expect_err("a scan the prover committed must be rejected");
    assert!(
        reason.contains("verifier cryptographic verification failed")
            && !reason.contains("panicked"),
        "{reason}"
    );
}
