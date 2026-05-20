//! End-to-end prove-and-verify quickstart.
//!
//! Walks through the four stages of the TruthTable pipeline over a small
//! TPC-H `lineitem` table, so you can see how the data owner, prover, and
//! verifier fit together:
//!
//! 1. **Setup** — generate proving / verifying keys.
//! 2. **Commit** — turn the parquet into an `.oracle` artifact the verifier can trust.
//! 3. **Prove** — run the SQL query and emit a proof plus the prover's claimed result.
//! 4. **Verify** — check the proof against the oracle and claimed result.
//!
//! The example is split into two phases for clarity:
//!
//! - **Build** — pre-declare every artifact path and construct all four
//!   stage runners. Nothing touches disk here.
//! - **Run** — execute each runner in order.
//!
//! Run from the repo root:
//!
//! ```bash
//! cargo run --release -p tt-exec --example quickstart
//! ```
//!
//! All artifacts (keys, oracle, proof, result) land under `artifacts/`.
//! Keys are reused across runs since generating them at size 2^19 is not
//! cheap; the oracle, proof, and verification are redone on every run.
//!
//! For the batteries-included version of this flow — oracle staleness
//! checks, TPC-H table resolution, test-suite plumbing — see
//! [`tt_exec::test_utils::prove_and_verify_query`].

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

    // --- Build phase: declare paths and construct every stage runner upfront. ---

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

    // --- Run phase: execute each stage in order. ---

    // 1. Setup — generate proving/verifying keys, reusing them if present.
    if !pk_path.exists() || !vk_path.exists() {
        setup.run()?;
    }

    // 2. Commit — build the oracle that the verifier can trust without seeing the table.
    commit.run().await?;

    // 3. Prove — run the query and emit a proof + the prover's claimed result.
    prove.run().await?;

    // 4. Verify — check the proof against the oracle and the claimed result.
    verify.run().await?;

    Ok(())
}

/// Materialize the TPC-H `lineitem` parquet on first run; reuse it thereafter.
fn ensure_lineitem_parquet() -> Result<PathBuf> {
    let path = test_data_path("lineitem.parquet");
    if !path.exists() {
        let dir = path.parent().expect("test_data_path always has a parent");
        generate_parquet_scale(0.0005, dir);
    }
    Ok(path)
}
