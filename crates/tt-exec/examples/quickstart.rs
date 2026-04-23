//! End-to-end prove-and-verify quickstart.
//!
//! Runs a single SQL query through the full truth-table pipeline — setup,
//! commit, prove, verify — over a small TPC-H `lineitem` table that is
//! auto-generated into `artifacts/test-data/` on the first run.
//!
//! Run from the repo root:
//!
//! ```bash
//! cargo run --release -p tt-exec --example quickstart
//! ```
//!
//! Expected output ends with `Proof verified successfully.` and exits 0.
//! Any verification failure or proving error is surfaced via the process
//! exit code.

use anyhow::Result;
use tt_exec::test_utils::prove_and_verify_query;

#[tokio::main]
async fn main() -> Result<()> {
    let query = "SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R'";
    prove_and_verify_query(query, &["lineitem"], None).await?;
    println!("Proof verified successfully.");
    Ok(())
}
