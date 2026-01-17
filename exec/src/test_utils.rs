use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ark_piop::test_utils::init_subscriber;

use crate::{
    commit::CommitBuilder,
    prove::ProveBuilder,
    runtime,
    setup::{DEFAULT_TEST_LOG_SIZE, SetupBuilder, default_pk_filename, default_vk_filename},
    verify::VerifyBuilder,
};
use tpch_data::{bench_data_path, test_data_path};

/// Executes an end-to-end proving and verification pipeline for the provided
/// query by delegating to the CLI runners defined in `prove` and `verify`.
/// The helper resolves the TPCH parquet and oracle assets for the supplied
/// `table_names`, generating them on the fly when missing.
pub async fn prove_and_verify_query(
    query: &str,
    table_names: &[&str],
    proof_output_path: Option<PathBuf>,
) -> Result<()> {
    init_subscriber();
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

    let proof_path = ProveBuilder::new()
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
        .with_parquet_paths(parquet_paths)
        .with_oracle_paths(oracle_paths)
        .with_proof_path(proof_path)
        .with_vk_path(vk_path)
        .build()?
        .run()
        .await
}

pub fn resolve_key_paths(log_size: usize) -> Result<(PathBuf, PathBuf)> {
    let cwd = std::env::current_dir().context("failed to determine current directory")?;
    let expected_pk = cwd.join(default_pk_filename(log_size));
    let expected_vk = cwd.join(default_vk_filename(log_size));

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
    let table_name = parquet_path
        .file_stem()
        .ok_or_else(|| anyhow!("parquet path must include a file name"))?
        .to_string_lossy()
        .to_string();
    let default_oracle = std::env::current_dir()
        .context("failed to determine current directory")?
        .join(format!("{table_name}.oracle"));

    if default_oracle.exists() {
        return Ok(default_oracle);
    }

    let output_root = default_oracle.parent().map(Path::to_path_buf);

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
