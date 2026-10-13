use std::path::{Path, PathBuf};
use tt_core::session::session_context;

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

type B = BenchBackend;

/// [`prove_and_verify_query`] over the bench-data parquets with the
/// bench-size keys (`DEFAULT_BENCH_LOG_SIZE`).
pub async fn prove_and_verify_query_bench(
    query: &str,
    table_names: &[&str],
    proof_output_path: Option<PathBuf>,
) -> Result<()> {
    init_test_tracing(jsonl_stats_enabled_from_env());
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

    // The `bench_query` span lets the JSONL layer key its events to this
    // query.
    async move {
        let outputs = ProveBuilder::new()
            .with_query(query.to_owned())
            .with_parquet_paths(parquet_paths.clone())
            .with_oracle_paths(oracle_paths.clone())
            .with_pk_path(pk_path)
            .with_output_path(Some(
                proof_output_path.clone().unwrap_or_else(unique_proof_path),
            ))
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

/// Proves and verifies `query` through the `prove` and `verify` runners,
/// generating the keys and the oracles of `table_names` when missing.
pub async fn prove_and_verify_query(
    query: &str,
    table_names: &[&str],
    proof_output_path: Option<PathBuf>,
) -> Result<()> {
    init_test_tracing(jsonl_stats_enabled_from_env());
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
            .with_output_path(Some(
                proof_output_path.clone().unwrap_or_else(unique_proof_path),
            ))
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

/// A proof path unique to the calling test. The default is one shared
/// `artifacts/proof.pi`, and `cargo test` runs tests as threads in one
/// process, so tests sharing it would verify each other's proofs. The harness
/// names each test thread after its test; the pid keeps concurrent
/// `cargo test` processes apart.
fn unique_proof_path() -> PathBuf {
    let thread = std::thread::current();
    let sanitized: String = thread
        .name()
        .unwrap_or("test")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    workspace_artifacts_dir().join(format!("{sanitized}.{}.pi", std::process::id()))
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
    // One commit at a time per parquet path: `cargo test` runs tests as
    // threads in one process. The lock is held across the check-then-build, so
    // a second caller for the same table finds the first caller's file.
    let lock = oracle_build_lock(parquet_path);
    let _guard = lock.lock().await;
    resolve_oracle_path_locked(parquet_path, pk_path).await
}

fn oracle_build_lock(parquet_path: &Path) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().expect("oracle lock registry poisoned");
    map.entry(parquet_path.to_path_buf())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Cache key for a committed oracle: everything the commitment depends on
/// that can change without the parquet path changing. That is the backend,
/// [`ORACLE_LAYOUT`], the size and modification time of the parquet and of the
/// proving key, and how the commit path encodes the table
/// ([`hash_sample_encoding`], which covers the fingerprint columns).
async fn oracle_cache_key(parquet_path: &Path, pk_path: &Path) -> Result<String> {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut h = DefaultHasher::new();
    hash_sample_encoding(parquet_path, &mut h).await?;
    BACKEND_NAME.hash(&mut h);
    ORACLE_LAYOUT.hash(&mut h);
    for path in [parquet_path, pk_path] {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("stat {} for the oracle cache key", path.display()))?;
        path.file_name().hash(&mut h);
        meta.len().hash(&mut h);
        if let Ok(modified) = meta.modified()
            && let Ok(since) = modified.duration_since(std::time::UNIX_EPOCH)
        {
            since.as_nanos().hash(&mut h);
        }
    }
    Ok(format!("{:016x}", h.finish()))
}

/// Bumped when the oracle files change without the encoding of the sample
/// changing.
const ORACLE_LAYOUT: u32 = 3;

/// Rows of the table run through the commit path's padding and
/// arithmetization for [`oracle_cache_key`]. A sample is enough to notice an
/// encoding change and keeps the key cheap for large tables.
const ENCODING_SAMPLE_ROWS: usize = 64;

/// Hashes the polynomials the commit path produces for the first
/// [`ENCODING_SAMPLE_ROWS`] rows of the table, using the same padding and
/// arithmetization functions a commitment goes through.
async fn hash_sample_encoding(
    parquet_path: &Path,
    hasher: &mut impl std::hash::Hasher,
) -> Result<()> {
    use ark_piop::SnarkBackend;
    use ark_serialize::CanonicalSerialize;
    use datafusion::{datasource::MemTable, prelude::ParquetReadOptions};
    use std::hash::Hash;
    use tt_core::prover::{
        passes::{
            arithmetization::arithmetize_materialized_table,
            materialization::pad_batches_to_power_of_two,
        },
        payloads::MaterializedTable,
    };

    let ctx = session_context();
    ctx.register_parquet(
        "sample",
        parquet_path
            .to_str()
            .context("parquet path must be valid UTF-8")?,
        ParquetReadOptions::default(),
    )
    .await
    .with_context(|| {
        format!(
            "register {} for the oracle cache key",
            parquet_path.display()
        )
    })?;
    let df = ctx
        .sql(&format!(
            "SELECT * EXCEPT ({}) FROM sample LIMIT {ENCODING_SAMPLE_ROWS}",
            arithmetic::ROW_ID_COL_NAME
        ))
        .await?;
    let schema = df.schema().as_arrow().clone();
    let (batches, row_count) = pad_batches_to_power_of_two(&schema, df.collect().await?)?;
    let table = MaterializedTable::new_with_batches(
        MemTable::try_new(std::sync::Arc::new(schema), vec![batches.clone()])?,
        row_count,
        batches,
    );
    let arith = arithmetize_materialized_table::<<B as SnarkBackend>::F>(
        &table,
        None,
        Some(&tt_core::prover::passes::arithmetization::FingerprintColumns::All),
    );
    let mut bytes = Vec::new();
    for (field, mle) in arith.polynomials() {
        field.name().hash(hasher);
        for eval in mle.evaluations() {
            bytes.clear();
            eval.serialize_compressed(&mut bytes)?;
            bytes.hash(hasher);
        }
    }
    Ok(())
}

async fn resolve_oracle_path_locked(parquet_path: &Path, pk_path: &Path) -> Result<PathBuf> {
    // `<stem>.<backend>.<key>.oracle`, next to the parquet. The key changes
    // whenever the commitment would, so an existing file is always current.
    let key = oracle_cache_key(parquet_path, pk_path).await?;
    let cached = parquet_path.with_extension(format!("{BACKEND_NAME}.{key}.oracle"));
    if cached.exists() && oracle_matches_parquet(&cached, parquet_path)? {
        return Ok(cached);
    }
    if cached.exists() {
        warn!(
            parquet = %parquet_path.display(),
            oracle = %cached.display(),
            "cached oracle does not match its parquet; regenerating"
        );
    }

    // Build under a unique temporary name, then rename into place: the rename
    // is atomic, so a reader in another process (the bench harness, a second
    // `cargo test` binary) never sees a partial file.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parquet_path.with_extension(format!(
        "{BACKEND_NAME}.{key}.tmp{}-{nonce}.oracle",
        std::process::id()
    ));
    let written = CommitBuilder::new()
        .with_parquet_path(parquet_path.to_path_buf())
        .with_pk_path(pk_path.to_path_buf())
        .with_output_path(Some(tmp.clone()))
        .build()?
        .run()
        .await?;
    // Bins before the oracle: a published oracle always has its bins.
    let written_bins = crate::paths::fingerprint_bins_path(&written);
    if written_bins.exists() {
        let cached_bins = crate::paths::fingerprint_bins_path(&cached);
        std::fs::rename(&written_bins, &cached_bins).with_context(|| {
            format!(
                "publish fingerprint bins {} -> {}",
                written_bins.display(),
                cached_bins.display()
            )
        })?;
    }
    std::fs::rename(&written, &cached).with_context(|| {
        format!(
            "publish oracle {} -> {}",
            written.display(),
            cached.display()
        )
    })?;
    Ok(cached)
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
