#![cfg(feature = "test-utils")]

//! Proving the same query over the same tables twice gives the same proof and
//! the same result, byte for byte.
//!
//! The prover commits to the rows its plan nodes produce, in the order they
//! come out. DataFusion's default session runs a plan in one partition per
//! core and merges partitions in the order their batches arrive, so under it
//! that order, and with it the proof, changes from run to run: an aggregate
//! or a join over a table of a few thousand rows gave a different proof on
//! nearly every run. The queries below are of those two kinds, and neither
//! sorts its output, so the result's row order is at stake too.
//!
//! The runtime is multi-threaded on purpose. On a current-thread runtime the
//! partitions of a plan are polled in a fixed order and the default session
//! mostly gets away with it.

use std::path::{Path, PathBuf};

use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::ProveBuilder,
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path},
};

const AGGREGATE: &str = "SELECT ps_partkey, min(ps_supplycost) FROM partsupp GROUP BY ps_partkey";
const JOIN: &str = "SELECT s_name, n_name FROM supplier, nation WHERE s_nationkey = n_nationkey";

/// Proof and result bytes of one run.
async fn prove(query: &str, tables: &[&str], pk: &Path, tag: &str) -> (Vec<u8>, Vec<u8>) {
    let mut parquets = Vec::new();
    let mut oracles = Vec::new();
    for table in tables {
        let parquet = resolve_parquet_path(table).expect("test parquet");
        oracles.push(
            resolve_oracle_path(&parquet, pk)
                .await
                .expect("table oracle"),
        );
        parquets.push(parquet);
    }
    let output: PathBuf =
        workspace_artifacts_dir().join(format!("determinism.{tag}.{}.pi", std::process::id()));
    let outputs = ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(parquets)
        .with_oracle_paths(oracles)
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(output))
        .build()
        .expect("prove builder")
        .run()
        .await
        .unwrap_or_else(|e| panic!("proof for `{query}` failed: {e:#}"));
    let bytes = (
        std::fs::read(&outputs.proof_path).expect("proof file"),
        std::fs::read(&outputs.result_path).expect("result file"),
    );
    let _ = std::fs::remove_file(&outputs.proof_path);
    let _ = std::fs::remove_file(&outputs.result_path);
    bytes
}

async fn assert_same_on_every_run(query: &str, tables: &[&str], tag: &str) {
    let (pk, _vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("test keys");
    let (proof, result) = prove(query, tables, &pk, &format!("{tag}.0")).await;
    for run in 1..4 {
        let (again, result_again) = prove(query, tables, &pk, &format!("{tag}.{run}")).await;
        assert!(
            result == result_again,
            "run {run} of `{query}` gave another result"
        );
        assert!(
            proof == again,
            "run {run} of `{query}` gave another proof for the same result"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aggregate_is_proved_the_same_way_every_time() {
    assert_same_on_every_run(AGGREGATE, &["partsupp"], "aggregate").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_is_proved_the_same_way_every_time() {
    assert_same_on_every_run(JOIN, &["supplier", "nation"], "join").await;
}
