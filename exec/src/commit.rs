use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use arithmetic::table_oracle::{ArithTableOracle, TrackedTableOracle};
use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable};
use ark_piop::{
    DefaultSnarkBackend, prover::ArgProver, setup::structs::SNARKVk, verifier::ArgVerifier,
};
use ark_serialize::CanonicalSerialize;
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use front_end::{
    prover::{TTProver, TTProverConfig},
    shared::TTSharedConfig,
};
use tt_core::{
    irs::{nodes::IsNode, payloads::PayloadStructure},
    prover::irs::TrackedIr,
};

use front_end::structs::{Artifact, TTPk};

type B = DefaultSnarkBackend;

pub struct CommitBuilder {
    parquet_path: Option<PathBuf>,
    pk_path: Option<PathBuf>,
    output_root: Option<PathBuf>,
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
        }
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

        Ok(CommitRunner {
            parquet_path,
            pk_path,
            output_path,
        })
    }
}

pub struct CommitRunner {
    parquet_path: PathBuf,
    pk_path: PathBuf,
    output_path: PathBuf,
}

impl CommitRunner {
    pub async fn run(&self) -> Result<PathBuf> {
        let parquet_path = self.parquet_path.clone();
        let pk_path = self.pk_path.clone();
        let output_path = self.output_path.clone();

        let written_path = commit_parquet_with_pk(&parquet_path, &pk_path, &output_path)
            .await
            .with_context(|| {
                format!(
                    "failed to commit parquet '{}' with proving key '{}'",
                    parquet_path.display(),
                    pk_path.display()
                )
            })?;

        Ok(written_path)
    }
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
) -> Result<PathBuf> {
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

    let query = format!("SELECT * EXCEPT ({}) FROM {table_name}", ACTIVATOR_COL_NAME);

    let (arg_prover, mut verifier) = load_prover_verifier(pk_path)
        .with_context(|| format!("failed to load proving key from {}", pk_path.display()))?;

    let shared_config: TTSharedConfig<B> = TTSharedConfig::with_defaults(ctx);
    let prover = TTProver::new(TTProverConfig::default(), shared_config, arg_prover);
    let (stages, mut arg_prover) = prover.build_ir_stages(&query).await?;
    let table_scan_table =
        table_scan_payload(&stages.tracked).context("table scan result not found in tracked IR")?;

    let proof = arg_prover.build_proof().context("build proof")?;
    verifier.set_proof(proof);

    let tracked_table_oracle =
        TrackedTableOracle::from_tracked_table(table_scan_table, &mut verifier)?;
    let serializable = ArithTableOracle::from_tracked_table_oracle(&tracked_table_oracle);

    write_oracle(&serializable, output_path)?;

    Ok(output_path.to_path_buf())
}

#[allow(clippy::type_complexity)]
fn load_prover_verifier(pk_path: &Path) -> Result<(ArgProver<B>, ArgVerifier<B>)> {
    let tt_pk = TTPk::<B>::load(pk_path).with_context(|| format!("load {}", pk_path.display()))?;
    let snark_pk = tt_pk.into_inner();
    let vk: SNARKVk<B> = snark_pk.vk.clone();
    let prover = ArgProver::new_from_pk(snark_pk);
    let verifier = ArgVerifier::new_from_vk(vk);
    Ok((prover, verifier))
}

fn write_oracle(serializable: &ArithTableOracle<B>, output_path: &Path) -> Result<()> {
    if let Some(parent) = output_path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let file = File::create(output_path)
        .with_context(|| format!("failed to create {}", output_path.display()))?;
    let mut writer = BufWriter::new(file);
    serializable
        .serialize_uncompressed(&mut writer)
        .context("failed to serialize oracle")?;
    writer
        .flush()
        .with_context(|| format!("failed to flush {}", output_path.display()))?;
    Ok(())
}

fn table_scan_payload(tracked_ir: &TrackedIr<B>) -> Result<TrackedTable<B>> {
    for (node_id, node) in tracked_ir.tree().arena() {
        if node.name() != "TableScan" {
            continue;
        }

        let payload = tracked_ir
            .payloads()
            .get(node_id)
            .and_then(|payload| payload.clone())
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table),
                _ => None,
            });

        if let Some(table) = payload {
            return Ok(table);
        }
    }

    Err(anyhow!("table scan payload not found"))
}
