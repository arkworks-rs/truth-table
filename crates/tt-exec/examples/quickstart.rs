//! Setup, commit, prove and verify one query over a small TPC-H `lineitem`.
//! Artifacts land under `artifacts/`; the keys are reused across runs.
//!
//! ```bash
//! cargo run --release -p tt-exec --example quickstart
//! ```

use std::path::PathBuf;

use anyhow::Result;
use tpch_data::{generate_parquet_scale, test_data_path};
use tt_exec::{
    commit::CommitBuilder,
    paths::workspace_artifacts_dir,
    prove::ProveBuilder,
    setup::{DEFAULT_TEST_LOG_SIZE, SetupBuilder, default_pk_filename, default_vk_filename},
    verify::VerifyBuilder,
};

#[tokio::main]
async fn main() -> Result<()> {
    let artifacts = workspace_artifacts_dir();
    let parquet = ensure_lineitem_parquet()?;
    let query = "SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R'";

    let pk_path = artifacts.join(default_pk_filename(DEFAULT_TEST_LOG_SIZE));
    let vk_path = artifacts.join(default_vk_filename(DEFAULT_TEST_LOG_SIZE));
    let oracle_path = artifacts.join("lineitem.oracle");
    let proof_path = artifacts.join("proof.pi");
    let result_path = artifacts.join("proof.result.parquet");

    let setup = SetupBuilder::new()
        .with_size_label(Some(DEFAULT_TEST_LOG_SIZE.to_string()))
        .with_pk_path(Some(pk_path.clone()))
        .with_vk_path(Some(vk_path.clone()))
        .build()?;

    let commit = CommitBuilder::new()
        .with_parquet_path(parquet.clone())
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(oracle_path.clone()))
        .build()?;

    let prove = ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_path(parquet)
        .with_oracle_path(oracle_path.clone())
        .with_pk_path(pk_path.clone())
        .with_output_path(Some(proof_path.clone()))
        .build()?;

    let verify = VerifyBuilder::new()
        .with_query(query.to_owned())
        .with_oracle_path(oracle_path)
        .with_proof_path(proof_path)
        .with_result_path(result_path)
        .with_vk_path(vk_path.clone())
        .build()?;

    if !pk_path.exists() || !vk_path.exists() {
        setup.run()?;
    }

    // The oracle is what the verifier trusts in place of the table.
    commit.run().await?;
    // Writes the proof and the claimed result.
    prove.run().await?;
    verify.run().await?;

    Ok(())
}

/// Generates the TPC-H `lineitem` parquet if it is missing.
fn ensure_lineitem_parquet() -> Result<PathBuf> {
    let path = test_data_path("lineitem.parquet");
    if !path.exists() {
        let dir = path.parent().expect("test_data_path always has a parent");
        generate_parquet_scale(0.0005, dir);
    }
    Ok(path)
}
