use std::path::{Path, PathBuf};

use crate::backend::{BACKEND_NAME, BenchBackend};
use anyhow::{Context, Result, anyhow};
use arithmetic::table_oracle::ArithTableOracle;
use ark_serialize::CanonicalDeserialize;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::fs::File;
use tracing::{Instrument, warn};

use crate::{
    commit::CommitBuilder,
    paths::workspace_artifacts_dir,
    prove::ProveBuilder,
    runtime,
    setup::{
        DEFAULT_BENCH_LOG_SIZE, DEFAULT_TEST_LOG_SIZE, SetupBuilder, default_pk_filename,
        default_vk_filename,
    },
    stats_jsonl::{jsonl_stats_enabled_from_env, query_stats_span},
    tracing_setup::init_test_tracing,
    verify::VerifyBuilder,
};
use tpch_data::{bench_data_path, test_data_path};

/// Init tracing for the test harness. When `TT_JSONL_STATS=1`, the
/// JSONL statistics layer is installed on top of the standard subscriber
/// so events on the `bench_stats` target (tracker snapshots, sumcheck
/// stream-decision logs, per-bucket stats) land in
/// `tt-results/raw/bench_stats.jsonl`. Otherwise falls back to the plain
/// subscriber — matches the historical behavior.
fn init_test_harness_tracing() {
    init_test_tracing(jsonl_stats_enabled_from_env());
}

type B = BenchBackend;

/// Executes an end-to-end proving and verification pipeline for the provided
/// query by delegating to the CLI runners defined in `prove` and `verify`.
/// The helper resolves the TPCH parquet and oracle assets for the supplied
/// `table_names`, generating them on the fly when missing.
/// Prove + verify a query against **bench-data** parquets using the
/// bench-size proving/verifying keys (`DEFAULT_BENCH_LOG_SIZE`). Used
/// by peak-RSS A/B benchmarks that need larger char-domain side polys
/// than test-data provides. Otherwise identical to
/// [`prove_and_verify_query`].
pub async fn prove_and_verify_query_bench(
    query: &str,
    table_names: &[&str],
    proof_output_path: Option<PathBuf>,
) -> Result<()> {
    init_test_harness_tracing();
    let parquet_paths = table_names
        .iter()
        .map(|name| {
            let path = bench_data_path(format!("{name}.parquet"));
            if !path.exists() {
                return Err(anyhow!(
                    "bench-data parquet for table '{name}' not found at {}",
                    path.display()
                ));
            }
            Ok(path)
        })
        .collect::<Result<Vec<_>>>()?;
    let (pk_path, vk_path) = resolve_key_paths(DEFAULT_BENCH_LOG_SIZE)?;
    let mut oracle_paths = Vec::with_capacity(parquet_paths.len());
    for parquet_path in &parquet_paths {
        let oracle = resolve_oracle_path(parquet_path, &pk_path).await?;
        oracle_paths.push(oracle);
    }

    // Wrap prove+verify in a `bench_query` span so the JSONL layer can
    // key events (tracker snapshots, sumcheck stream-decision logs,
    // per-bucket stats) back to this specific query. No-op when the
    // JSONL layer isn't installed (span is just an inert info-level
    // span).
    async move {
        let outputs = ProveBuilder::new()
            .with_query(query.to_owned())
            .with_parquet_paths(parquet_paths.clone())
            .with_oracle_paths(oracle_paths.clone())
            .with_pk_path(pk_path)
            .with_output_path(proof_output_path.clone())
            .build()?
            .run()
            .await?;

        VerifyBuilder::new()
            .with_query(query.to_owned())
            .with_oracle_paths(oracle_paths)
            .with_proof_path(outputs.proof_path)
            .with_result_path(outputs.result_path)
            .with_vk_path(vk_path)
            .build()?
            .run()
            .await
    }
    .instrument(query_stats_span(query))
    .await
}

pub async fn prove_and_verify_query(
    query: &str,
    table_names: &[&str],
    proof_output_path: Option<PathBuf>,
) -> Result<()> {
    init_test_harness_tracing();
    let parquet_paths = table_names
        .iter()
        .map(|name| resolve_parquet_path(name))
        .collect::<Result<Vec<_>>>()?;
    let (pk_path, vk_path) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE)?;
    let mut oracle_paths = Vec::with_capacity(parquet_paths.len());
    for parquet_path in &parquet_paths {
        let oracle = resolve_oracle_path(parquet_path, &pk_path).await?;
        oracle_paths.push(oracle);
    }

    async move {
        let outputs = ProveBuilder::new()
            .with_query(query.to_owned())
            .with_parquet_paths(parquet_paths.clone())
            .with_oracle_paths(oracle_paths.clone())
            .with_pk_path(pk_path)
            .with_output_path(proof_output_path.clone())
            .build()?
            .run()
            .await?;

        VerifyBuilder::new()
            .with_query(query.to_owned())
            .with_oracle_paths(oracle_paths)
            .with_proof_path(outputs.proof_path)
            .with_result_path(outputs.result_path)
            .with_vk_path(vk_path)
            .build()?
            .run()
            .await
    }
    .instrument(query_stats_span(query))
    .await
}

pub fn resolve_key_paths(log_size: usize) -> Result<(PathBuf, PathBuf)> {
    let artifacts_dir = workspace_artifacts_dir();
    let expected_pk = artifacts_dir.join(default_pk_filename(log_size));
    let expected_vk = artifacts_dir.join(default_vk_filename(log_size));

    if expected_pk.exists() && expected_vk.exists() {
        return Ok((expected_pk, expected_vk));
    }

    let mut builder = SetupBuilder::new().with_size_label(Some(log_size.to_string()));
    if expected_pk.exists() {
        builder = builder.with_pk_path(Some(expected_pk.clone()));
    }
    if expected_vk.exists() {
        builder = builder.with_vk_path(Some(expected_vk.clone()));
    }

    let runner = builder.build()?;
    runner.run()?;
    Ok((expected_pk, expected_vk))
}

pub async fn resolve_oracle_path(parquet_path: &Path, pk_path: &Path) -> Result<PathBuf> {
    // Namespace by curve: oracle files contain commitments specific to the active
    // backend, so BN254 and BLS12-381 runs cannot share `.oracle` artifacts.
    let parquet_oracle = parquet_path.with_extension(format!("{BACKEND_NAME}.oracle"));
    if parquet_oracle.exists() && oracle_matches_parquet(&parquet_oracle, parquet_path)? {
        return Ok(parquet_oracle);
    }
    if parquet_oracle.exists() {
        warn!(
            parquet = %parquet_path.display(),
            oracle = %parquet_oracle.display(),
            "stale oracle detected; regenerating from parquet"
        );
    }

    let output_root = parquet_oracle.parent().map(Path::to_path_buf);

    let oracle_path = CommitBuilder::new()
        .with_parquet_path(parquet_path.to_path_buf())
        .with_pk_path(pk_path.to_path_buf())
        .with_output_path(output_root)
        .build()?
        .run()
        .await?;

    Ok(oracle_path)
}

pub fn resolve_oracle_path_blocking(parquet_path: &Path, pk_path: &Path) -> Result<PathBuf> {
    runtime::block_on(resolve_oracle_path(parquet_path, pk_path))
}

pub fn resolve_parquet_path(table_name: &str) -> Result<PathBuf> {
    let candidate = test_data_path(format!("{table_name}.parquet"));
    if candidate.exists() {
        return Ok(candidate);
    }

    let bench_candidate = bench_data_path(format!("{table_name}.parquet"));
    if bench_candidate.exists() {
        return Ok(bench_candidate);
    }

    Err(anyhow!(
        "could not locate parquet file for table '{table_name}'"
    ))
}

fn oracle_matches_parquet(oracle_path: &Path, parquet_path: &Path) -> Result<bool> {
    let oracle_log_size = load_oracle_log_size(oracle_path)?;
    let parquet_log_size = parquet_log_size(parquet_path)?;
    Ok(oracle_log_size == parquet_log_size)
}

fn load_oracle_log_size(oracle_path: &Path) -> Result<usize> {
    let file = File::open(oracle_path)
        .with_context(|| format!("failed to open oracle file {}", oracle_path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let oracle = ArithTableOracle::<B>::deserialize_compressed(&mut reader)
        .with_context(|| format!("failed to deserialize oracle {}", oracle_path.display()))?;
    Ok(oracle.log_size())
}

fn parquet_log_size(parquet_path: &Path) -> Result<usize> {
    let file = File::open(parquet_path)
        .with_context(|| format!("failed to open parquet file {}", parquet_path.display()))?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .with_context(|| format!("failed to read parquet metadata {}", parquet_path.display()))?;
    let total_rows = builder.metadata().file_metadata().num_rows() as usize;
    let padded_rows = total_rows.max(1).next_power_of_two();
    Ok(padded_rows.ilog2() as usize)
}
