use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::{DefaultSnarkBackend, prover::ArgProver};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use datafusion::{
    config::ConfigOptions,
    optimizer::{Analyzer, Optimizer, OptimizerContext},
    prelude::{ParquetReadOptions, SessionContext},
};
use front_end::{
    prover::{TTProver, TTProverConfig},
    shared::TTSharedConfig,
    structs::{Artifact, TTPk, TTProof},
};
use indexmap::IndexMap;
use tracing::instrument;
use truthtable_core::ctx_oracles::CtxOracles;

use crate::{
    runtime,
    setup::{DEFAULT_LOG_SIZE, default_pk_filename},
};

type B = DefaultSnarkBackend;

pub struct ProveBuilder {
    query: Option<String>,
    parquet_paths: Option<Vec<PathBuf>>,
    oracle_paths: Option<Vec<PathBuf>>,
    pk_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
}

impl Default for ProveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProveBuilder {
    pub fn new() -> Self {
        Self {
            query: None,
            parquet_paths: None,
            oracle_paths: None,
            pk_path: None,
            output_path: None,
        }
    }

    pub fn with_query(mut self, query: String) -> Self {
        self.query = Some(query);
        self
    }

    pub fn with_parquet_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.parquet_paths = Some(paths);
        self
    }

    pub fn with_parquet_path(self, path: PathBuf) -> Self {
        self.with_parquet_paths(vec![path])
    }

    pub fn with_oracle_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.oracle_paths = Some(paths);
        self
    }

    pub fn with_oracle_path(self, path: PathBuf) -> Self {
        self.with_oracle_paths(vec![path])
    }

    pub fn with_pk_path(mut self, path: PathBuf) -> Self {
        self.pk_path = Some(path);
        self
    }

    pub fn with_output_path(mut self, path: Option<PathBuf>) -> Self {
        self.output_path = path;
        self
    }

    #[instrument(level = "debug", skip_all)]
    pub fn build(self) -> Result<ProveRunner> {
        let query = self.query.context("query string is required")?;
        let parquet_paths = self
            .parquet_paths
            .filter(|paths| !paths.is_empty())
            .context("at least one parquet path is required for prove")?;
        let oracle_paths = self
            .oracle_paths
            .filter(|paths| !paths.is_empty())
            .context("at least one oracle path is required for prove")?;

        if parquet_paths.len() != oracle_paths.len() {
            return Err(anyhow!(
                "number of parquet paths ({}) must match number of oracle paths ({})",
                parquet_paths.len(),
                oracle_paths.len()
            ));
        }

        let output_path = resolve_output_path(self.output_path)?;

        Ok(ProveRunner {
            query,
            parquet_paths,
            oracle_paths,
            pk_path: self.pk_path,
            output_path,
        })
    }
}

pub struct ProveRunner {
    query: String,
    parquet_paths: Vec<PathBuf>,
    oracle_paths: Vec<PathBuf>,
    pk_path: Option<PathBuf>,
    output_path: PathBuf,
}

pub struct PreparedProverArtifacts {
    prover: TTProver<B>,
    query: String,
}

impl ProveRunner {
    #[instrument(level = "debug", skip_all)]
    pub async fn run(&self) -> Result<PathBuf> {
        let (path, _) = self.run_with_build_timing().await?;
        Ok(path)
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn run_with_build_timing(&self) -> Result<(PathBuf, Duration)> {
        let artifacts = self.prepare_prover_artifacts().await?;
        let start = Instant::now();
        let proof = artifacts.build_proof().await?;
        let elapsed = start.elapsed();
        write_proof(&proof, &self.output_path)?;
        Ok((self.output_path.clone(), elapsed))
    }

    #[instrument(level = "debug", skip_all)]
    async fn prepare_prover_artifacts(&self) -> Result<PreparedProverArtifacts> {
        prepare_prover_artifacts(
            &self.query,
            &self.parquet_paths,
            &self.oracle_paths,
            self.pk_path.as_deref(),
        )
        .await
    }

    #[instrument(level = "debug", skip_all)]
    pub fn run_blocking(&self) -> Result<PathBuf> {
        runtime::block_on(self.run())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn prepare_prover_artifacts_blocking(&self) -> Result<PreparedProverArtifacts> {
        runtime::block_on(self.prepare_prover_artifacts())
    }
}

#[instrument(level = "debug", skip_all)]
pub async fn prepare_prover_artifacts(
    query: &str,
    parquet_paths: &[PathBuf],
    oracle_paths: &[PathBuf],
    pk_path: Option<&Path>,
) -> Result<PreparedProverArtifacts> {
    let ctx = SessionContext::new();
    for parquet_path in parquet_paths {
        if !parquet_path.exists() {
            return Err(anyhow!(
                "parquet file not found: {} (try tpch-data/test-data/<table>.parquet)",
                parquet_path.display()
            ));
        }
        if !parquet_path.is_file() {
            return Err(anyhow!(
                "parquet path is not a file: {}",
                parquet_path.display()
            ));
        }

        let table_name = parquet_path
            .file_stem()
            .ok_or_else(|| anyhow!("parquet path must have a file name"))?
            .to_string_lossy()
            .to_string();

        ctx.register_parquet(
            &table_name,
            parquet_path
                .to_str()
                .context("parquet path must be valid UTF-8")?,
            ParquetReadOptions::default(),
        )
        .await
        .with_context(|| format!("failed to register parquet {}", parquet_path.display()))?;
    }

    let ctx_oracles = ctx_oracles_from_paths(oracle_paths)?;
    let shared_config = build_shared_config(ctx, ctx_oracles);
    let arg_prover = load_arg_prover(pk_path, oracle_paths)?;
    let prover = TTProver::new(TTProverConfig::default(), shared_config, arg_prover);

    Ok(PreparedProverArtifacts {
        prover,
        query: query.to_string(),
    })
}

#[instrument(level = "debug", skip_all)]
pub fn prepare_prover_artifacts_blocking(
    query: &str,
    parquet_paths: &[PathBuf],
    oracle_paths: &[PathBuf],
    pk_path: Option<&Path>,
) -> Result<PreparedProverArtifacts> {
    runtime::block_on(prepare_prover_artifacts(
        query,
        parquet_paths,
        oracle_paths,
        pk_path,
    ))
}

impl PreparedProverArtifacts {
    #[instrument(level = "debug", skip_all)]
    async fn build_proof(self) -> Result<TTProof<B>> {
        let (_, proof) = self.prover.prove(&self.query).await?;
        Ok(proof)
    }
}

#[instrument(level = "debug", skip_all)]
pub fn build_proof_from_artifacts(
    artifacts: PreparedProverArtifacts,
) -> Result<TTProof<B>> {
    runtime::block_on(artifacts.build_proof())
}

#[instrument(level = "debug", skip_all)]
fn ctx_oracles_from_paths(oracle_paths: &[PathBuf]) -> Result<CtxOracles<B>> {
    let mut table_oracles = IndexMap::new();
    for oracle_path in oracle_paths {
        let oracle = load_oracle(oracle_path)?;
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow!("oracle {} missing schema", oracle_path.display()))?;
        table_oracles.insert(schema, oracle.clone());
    }

    Ok(CtxOracles::new(table_oracles))
}

fn build_shared_config(
    session_ctx: SessionContext,
    ctx_oracles: CtxOracles<B>,
) -> TTSharedConfig<B> {
    TTSharedConfig::new(
        Analyzer::with_rules(proof_planner::logical_plan_analyzer::rules()),
        Optimizer::with_rules(proof_planner::logical_plan_optimizer::rules()),
        ctx_oracles,
        session_ctx,
        ConfigOptions::new(),
        OptimizerContext::new(),
        |_plan_after_rule, _rule| {},
    )
}

#[instrument(level = "debug", skip_all)]
fn load_arg_prover(pk_path: Option<&Path>, oracle_paths: &[PathBuf]) -> Result<ArgProver<B>> {
    let pk_path = match pk_path {
        Some(path) => path.to_path_buf(),
        None => {
            let oracle_path = oracle_paths
                .first()
                .ok_or_else(|| anyhow!("at least one oracle path is required for prove"))?;
            resolve_pk_path(oracle_path)?
        }
    };

    let tt_pk = TTPk::<B>::load(&pk_path)
        .with_context(|| format!("read proving key {}", pk_path.display()))?;
    Ok(ArgProver::new_from_pk(tt_pk.into_inner()))
}

#[instrument(level = "debug", skip_all)]
fn load_oracle(path: &Path) -> Result<ArithTableOracle<B>> {
    if !path.exists() {
        return Err(anyhow!(
            "oracle file not found: {} (run `tt commit` to generate it)",
            path.display()
        ));
    }
    if !path.is_file() {
        return Err(anyhow!("oracle path is not a file: {}", path.display()));
    }

    let file = File::open(path)
        .with_context(|| format!("failed to open oracle file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    ArithTableOracle::<B>::deserialize_uncompressed_unchecked(&mut reader)
        .context("failed to deserialize oracle")
}

#[instrument(level = "debug", skip_all)]
fn resolve_pk_path(oracle_path: &Path) -> Result<PathBuf> {
    let file_name = default_pk_filename(DEFAULT_LOG_SIZE);
    let mut candidates = Vec::new();
    if let Some(parent) = oracle_path.parent() {
        candidates.push(parent.join(&file_name));
    }

    let cwd_candidate = std::env::current_dir()
        .context("failed to resolve current working directory")?
        .join(&file_name);
    if !candidates.contains(&cwd_candidate) {
        candidates.push(cwd_candidate);
    }

    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    Err(anyhow!(
        "could not locate proving key '{file_name}'. looked in: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[instrument(level = "debug", skip_all)]
fn resolve_output_path(requested: Option<PathBuf>) -> Result<PathBuf> {
    const DEFAULT_PROOF_FILE: &str = "proof.pi";

    match requested {
        Some(path) => {
            if path.extension().is_some() {
                Ok(path)
            } else {
                Ok(path.join(DEFAULT_PROOF_FILE))
            }
        }
        None => Ok(std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(DEFAULT_PROOF_FILE)),
    }
}

#[instrument(level = "debug", skip_all)]
fn write_proof(proof: &TTProof<B>, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let file = File::create(path)
        .with_context(|| format!("failed to create proof file {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    proof
        .as_inner()
        .serialize_uncompressed(&mut writer)
        .context("failed to serialize proof")?;
    writer
        .flush()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    Ok(())
}
