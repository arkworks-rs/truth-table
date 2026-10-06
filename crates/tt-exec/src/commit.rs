use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::backend::BenchBackend;
use anyhow::{Context, Result, anyhow, bail};
use arithmetic::{
    ACTIVATOR_COL_NAME, ROW_ID_COL_NAME,
    fingerprint::{FingerprintRules, NUM_BINS},
    table_oracle::ArithTableOracle,
};
use ark_serialize::CanonicalSerialize;
use datafusion::{
    arrow::{array::AsArray, datatypes::DataType},
    prelude::{ParquetReadOptions, SessionContext},
};
use front_end::{
    data_owner::{TTDataOwner, TTDataOwnerConfig},
    shared::TTSharedConfig,
};
use tracing::info;
use tt_core::prover::passes::materialization::configure_constraint_metadata_from_parquet_paths;

use front_end::structs::{Artifact, TTPk};

type B = BenchBackend;

pub struct CommitBuilder {
    parquet_path: Option<PathBuf>,
    pk_path: Option<PathBuf>,
    output_root: Option<PathBuf>,
    fp_width: Option<usize>,
}

impl Default for CommitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitBuilder {
    pub fn new() -> Self {
        Self {
            parquet_path: None,
            pk_path: None,
            output_root: None,
            fp_width: None,
        }
    }

    /// Bins of every string column's rule; without one, [`NUM_BINS`]. Zero
    /// commits no fingerprints.
    pub fn with_fp_width(mut self, width: Option<usize>) -> Self {
        self.fp_width = width;
        self
    }

    pub fn with_parquet_path(mut self, path: PathBuf) -> Self {
        self.parquet_path = Some(path);
        self
    }

    pub fn with_pk_path(mut self, path: PathBuf) -> Self {
        self.pk_path = Some(path);
        self
    }

    pub fn with_output_path(mut self, path: Option<PathBuf>) -> Self {
        self.output_root = path;
        self
    }

    pub fn build(self) -> Result<CommitRunner> {
        let parquet_path = self
            .parquet_path
            .context("parquet path is required for commit")?;
        let pk_path = self.pk_path.context("pk-path is required for commit")?;
        let output_path = resolve_output_path(&parquet_path, self.output_root.clone())?;

        let fp_width = self.fp_width.unwrap_or(NUM_BINS);
        if fp_width > NUM_BINS {
            bail!("--fp-bins {fp_width} is more than {NUM_BINS}");
        }
        Ok(CommitRunner {
            parquet_path,
            pk_path,
            output_path,
            fp_width,
        })
    }
}

pub struct CommitRunner {
    parquet_path: PathBuf,
    pk_path: PathBuf,
    output_path: PathBuf,
    fp_width: usize,
}

impl CommitRunner {
    pub async fn run(&self) -> Result<PathBuf> {
        Ok(self.run_with_timing().await?.0)
    }

    /// Commit, returning the oracle path and the time spent building the
    /// fingerprint rules, encoding and committing: loading the proving key
    /// and writing the oracle are not counted.
    pub async fn run_with_timing(&self) -> Result<(PathBuf, Duration)> {
        let parquet_path = self.parquet_path.clone();
        let pk_path = self.pk_path.clone();
        let output_path = self.output_path.clone();

        info!(width = self.fp_width, "fingerprint width");
        let elapsed = commit_parquet_with_pk(&parquet_path, &pk_path, &output_path, self.fp_width)
            .await
            .with_context(|| {
                format!(
                    "failed to commit parquet '{}' with proving key '{}'",
                    parquet_path.display(),
                    pk_path.display()
                )
            })?;
        info!(seconds = elapsed.as_secs_f64(), "committed");
        Ok((output_path, elapsed))
    }
}

/// The rule of `width` bins for every string column, built from its
/// active rows.
async fn column_rules(ctx: &SessionContext, table: &str, width: usize) -> Result<FingerprintRules> {
    let mut rules = FingerprintRules::default();
    let schema = ctx.table(table).await?.schema().as_arrow().clone();
    let active = if schema.index_of(ACTIVATOR_COL_NAME).is_ok() {
        format!(" WHERE \"{ACTIVATOR_COL_NAME}\"")
    } else {
        String::new()
    };
    for field in schema.fields() {
        let column = field.name();
        let is_string = matches!(
            field.data_type(),
            DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View
        );
        if !is_string {
            continue;
        }
        let batches = ctx
            .sql(&format!("SELECT \"{column}\" FROM {table}{active}"))
            .await?
            .collect()
            .await?;
        let mut strings: Vec<&str> = Vec::new();
        for batch in &batches {
            let values = batch.column(0);
            // NULL fingerprints as the empty string, as the encoder does.
            match values.data_type() {
                DataType::Utf8 => strings.extend(
                    values
                        .as_string::<i32>()
                        .iter()
                        .map(Option::unwrap_or_default),
                ),
                DataType::LargeUtf8 => strings.extend(
                    values
                        .as_string::<i64>()
                        .iter()
                        .map(Option::unwrap_or_default),
                ),
                _ => strings.extend(
                    values
                        .as_string_view()
                        .iter()
                        .map(Option::unwrap_or_default),
                ),
            }
        }
        let config = arithmetic::fingerprint::column_rule(column, &strings, width);
        info!(
            column,
            rows = strings.len(),
            bins = config.bins,
            "fingerprint rule"
        );
        rules.columns.insert(column.clone(), config);
    }
    Ok(rules)
}

fn resolve_output_path(parquet_path: &Path, requested: Option<PathBuf>) -> Result<PathBuf> {
    let default_name = default_output_filename(parquet_path)?;

    match requested {
        Some(path) => {
            if path.extension().is_some() {
                let mut file_path = path;
                file_path.set_extension("oracle");
                Ok(file_path)
            } else {
                Ok(path.join(default_name))
            }
        }
        None => {
            let base =
                std::env::current_dir().context("failed to resolve current working directory")?;
            Ok(base.join(default_name))
        }
    }
}

fn default_output_filename(parquet_path: &Path) -> Result<PathBuf> {
    let stem = parquet_path
        .file_stem()
        .ok_or_else(|| anyhow!("parquet path must include a file name"))?;
    let mut name = PathBuf::from(stem);
    name.set_extension("oracle");
    Ok(name)
}

async fn commit_parquet_with_pk(
    parquet_path: &Path,
    pk_path: &Path,
    output_path: &Path,
    width: usize,
) -> Result<Duration> {
    let snark_pk = load_snark_pk(pk_path)
        .with_context(|| format!("failed to load proving key from {}", pk_path.display()))?;
    let start = Instant::now();
    configure_constraint_metadata_from_parquet_paths(&[parquet_path.to_path_buf()]);
    let table_name = parquet_path
        .file_stem()
        .ok_or_else(|| anyhow!("parquet path must have a file name"))?
        .to_string_lossy()
        .to_string();

    let ctx = SessionContext::new();
    ctx.register_parquet(
        &table_name,
        parquet_path
            .to_str()
            .context("parquet path must be valid UTF-8")?,
        ParquetReadOptions::default(),
    )
    .await
    .context("failed to register parquet")?;

    // Install the rules BEFORE encoding: they decide how each string column
    // is fingerprinted, and they are recorded in the oracle so prover and
    // verifier reproduce exactly this encoding.
    let rules = column_rules(&ctx, &table_name, width).await?;
    arithmetic::fingerprint::configure_rules(rules)
        .map_err(|e| anyhow!("install fingerprint rules: {e}"))?;

    let query = format!("SELECT * EXCEPT ({}) FROM {table_name}", ROW_ID_COL_NAME);

    let shared_config: TTSharedConfig<B> = TTSharedConfig::with_defaults(ctx);
    let data_owner = TTDataOwner::new(TTDataOwnerConfig::default(), shared_config, snark_pk);
    // The verifier's oracle keeps one Merkle root per fingerprinted column;
    // the bins themselves go to the prover alone.
    let serializable = data_owner.commit(&query).await?.seal_fingerprints();
    let elapsed = start.elapsed();

    write_oracle(&serializable, output_path)?;

    Ok(elapsed)
}

fn load_snark_pk(pk_path: &Path) -> Result<ark_piop::setup::structs::SNARKPk<B>> {
    let tt_pk = TTPk::<B>::load(pk_path).with_context(|| format!("load {}", pk_path.display()))?;
    Ok(tt_pk.into_inner())
}

fn write_oracle(serializable: &ArithTableOracle<B>, output_path: &Path) -> Result<()> {
    if let Some(parent) = output_path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    // The bins first: an oracle on disk means its bins are there too.
    let bins_path = crate::paths::fingerprint_bins_path(output_path);
    if serializable.fingerprints().is_empty() {
        if bins_path.exists() {
            fs::remove_file(&bins_path)
                .with_context(|| format!("failed to remove stale {}", bins_path.display()))?;
        }
    } else {
        let file = File::create(&bins_path)
            .with_context(|| format!("failed to create {}", bins_path.display()))?;
        let mut writer = BufWriter::new(file);
        serializable
            .serialize_fingerprint_bins(&mut writer)
            .context("failed to serialize fingerprint bins")?;
        writer
            .flush()
            .with_context(|| format!("failed to flush {}", bins_path.display()))?;
    }

    let file = File::create(output_path)
        .with_context(|| format!("failed to create {}", output_path.display()))?;
    let mut writer = BufWriter::new(file);
    serializable
        .serialize_compressed(&mut writer)
        .context("failed to serialize oracle")?;
    writer
        .flush()
        .with_context(|| format!("failed to flush {}", output_path.display()))?;
    Ok(())
}
