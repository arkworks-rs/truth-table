#![cfg(feature = "test-utils")]
//! A dishonest prover marks a filter that keeps rows as proved empty and
//! claims the empty result. The pruning above the filter and the result
//! check then agree with the claim, so only the zerocheck on the filter's
//! activator can reject.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::path::{Path, PathBuf};

use datafusion::arrow::record_batch::RecordBatch;
use tt_core::test_utils::dishonest_prover::{set_claimed_result, set_empty_first_filter};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread},
};

/// The filter keeps 4 of region's 5 rows, too many to compact, so the plan
/// has no compaction for the forged pruning to move.
const QUERY: &str = "SELECT n_name, r_name FROM nation JOIN region ON n_regionkey = r_regionkey \
                     WHERE r_regionkey < 4";

const TABLES: [&str; 2] = ["nation", "region"];

async fn prove(pk: &Path, oracles: &[PathBuf], tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(QUERY.to_owned())
        .with_parquet_paths(
            TABLES
                .iter()
                .map(|table| resolve_parquet_path(table).expect("test parquet"))
                .collect(),
        )
        .with_oracle_paths(oracles.to_vec())
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(workspace_artifacts_dir().join(format!(
            "empty_subtree_forgery.{tag}.{}.pi",
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
async fn a_non_empty_filter_claimed_empty_is_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let mut oracles = Vec::new();
    for table in TABLES {
        let parquet = resolve_parquet_path(table).expect("test parquet");
        oracles.push(
            resolve_oracle_path(&parquet, &pk)
                .await
                .expect("test oracle"),
        );
    }

    let honest = prove(&pk, &oracles, "honest").await;
    verify_on_thread(
        QUERY,
        oracles.clone(),
        &honest.proof_path,
        &honest.result_path,
        &vk,
    )
    .expect("the honest proof must verify; otherwise the rejection below proves nothing");

    let forged = {
        let _forgery = set_empty_first_filter();
        let _claimed = set_claimed_result(Box::new(|batches: Vec<RecordBatch>| {
            batches.iter().map(|batch| batch.slice(0, 0)).collect()
        }));
        prove(&pk, &oracles, "forged").await
    };
    match verify_on_thread(QUERY, oracles, &forged.proof_path, &forged.result_path, &vk) {
        Ok(()) => panic!("a non-empty filter claimed empty verified"),
        Err(reason) => assert!(
            reason.contains("verifier cryptographic verification failed")
                && !reason.contains("panicked"),
            "rejected for another reason: {reason}"
        ),
    }
}
