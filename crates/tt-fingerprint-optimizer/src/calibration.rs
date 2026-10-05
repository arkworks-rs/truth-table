//! Drive the real prover on one LIKE query so the cost model
//! ([`crate::model::CostModel`]) can be fitted to measured whole-prove times
//! instead of hand-transcribed constants.
//!
//! A measured point is the query's [`crate::model::Shape`] under the active
//! scheme (computed offline with the same encoder the prover uses) plus the
//! wall time of proving it; the `tt-fp-calibrate` binary prints exactly
//! that row.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};

use tpch_data::bench_data_path;
use tt_exec::prove::ProveBuilder;
use tt_exec::setup::DEFAULT_BENCH_LOG_SIZE;
use tt_exec::test_utils::{resolve_key_paths, resolve_oracle_path_blocking};

use crate::corpus::Corpus;

/// Table / column the model is calibrated on — the lineitem `l_comment`
/// corpus of the release bench.
pub const CORPUS_TABLE: &str = "lineitem";
pub const CORPUS_COLUMN: &str = "l_comment";
pub const PROJECTION_COL: &str = "l_returnflag";
pub const ACTIVATOR_COL: &str = "__activator__";

/// Load the calibration corpus (active `l_comment` rows only).
pub fn load_corpus() -> Result<Corpus> {
    let parquet = bench_data_path(format!("{CORPUS_TABLE}.parquet"));
    Corpus::from_parquet(&parquet, CORPUS_COLUMN, Some(ACTIVATOR_COL))
        .with_context(|| format!("load calibration corpus from {}", parquet.display()))
}

/// Resolve the (parquet, oracle, pk) assets for the lineitem bench table,
/// generating the oracle on the fly if missing.
fn resolve_assets() -> Result<(PathBuf, PathBuf, PathBuf)> {
    let (pk_path, _vk_path) = resolve_key_paths(DEFAULT_BENCH_LOG_SIZE)
        .context("resolve bench proving/verifying keys")?;
    let parquet = bench_data_path(format!("{CORPUS_TABLE}.parquet"));
    if !parquet.exists() {
        anyhow::bail!(
            "bench-data parquet not found at {} (run `tt data-gen --bench` first)",
            parquet.display()
        );
    }
    let oracle = resolve_oracle_path_blocking(&parquet, &pk_path)
        .with_context(|| format!("resolve/commit oracle for {}", parquet.display()))?;
    Ok((parquet, oracle, pk_path))
}

/// Whole-prove wall time for `SELECT l_returnflag FROM lineitem WHERE
/// l_comment LIKE 'pattern'` under the production planner (the prover picks
/// the pre-filter's bins).
///
/// Synchronous, mirroring the bench harness: the blocking asset resolvers
/// run in this sync context (before any runtime is entered, so their own
/// `block_on` never nests), then the async prover is driven by a fresh
/// tokio runtime — DataFusion needs a live tokio reactor, which a
/// non-tokio executor would not provide.
pub fn prove_pattern_seconds(pattern: &str) -> Result<Duration> {
    let (parquet, oracle, pk_path) = resolve_assets()?;
    let query = format!(
        "SELECT {PROJECTION_COL} FROM {CORPUS_TABLE} WHERE {CORPUS_COLUMN} LIKE '{pattern}'"
    );
    let runner = ProveBuilder::new()
        .with_query(query)
        .with_parquet_paths(vec![parquet])
        .with_oracle_paths(vec![oracle])
        .with_pk_path(pk_path)
        .build()
        .context("build prove runner")?;
    // Current-thread runtime, matching `#[tokio::test]`: the prover's heavy
    // compute is rayon-parallel, so tokio only drives I/O. A multi-thread
    // runtime here spawns num_cpus tokio workers that oversubscribe against
    // rayon's num_cpus pool — measured 7-27x slower on the same prove.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    let (_outputs, elapsed) = runtime
        .block_on(runner.run_with_build_timing())
        .context("run prover")?;
    Ok(elapsed)
}
