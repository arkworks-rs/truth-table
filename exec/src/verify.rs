use anyhow::{Context, Result, anyhow};
use crate::prove::ProveBuilder;
use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::{DefaultSnarkBackend, verifier::ArgVerifier};
use ark_serialize::CanonicalDeserialize;
use datafusion::{
    config::ConfigOptions,
    optimizer::{Analyzer, Optimizer, OptimizerContext},
    prelude::{ParquetReadOptions, SessionContext},
};
use front_end::{
    shared::TTSharedConfig,
    structs::{Artifact, TTProof, TTVk},
    verifier::{TTVerifier, TTVerifierConfig},
};
use indexmap::IndexMap;
use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};
use tt_core::ctx_oracles::CtxOracles;

type B = DefaultSnarkBackend;

pub struct VerifyBuilder {
    query: Option<String>,
    parquet_paths: Option<Vec<PathBuf>>,
    oracle_paths: Option<Vec<PathBuf>>,
    proof_path: Option<PathBuf>,
    vk_path: Option<PathBuf>,
}

impl Default for VerifyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifyBuilder {
    pub fn new() -> Self {
        Self {
            query: None,
            parquet_paths: None,
            oracle_paths: None,
            proof_path: None,
            vk_path: None,
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

    pub fn with_proof_path(mut self, path: PathBuf) -> Self {
        self.proof_path = Some(path);
        self
    }

    pub fn with_vk_path(mut self, path: PathBuf) -> Self {
        self.vk_path = Some(path);
        self
    }

    pub fn build(self) -> Result<VerifyRunner> {
        let query = self.query.context("query string is required")?;
        let parquet_paths = self
            .parquet_paths
            .filter(|paths| !paths.is_empty())
            .context("at least one parquet path is required for verify")?;
        let oracle_paths = self
            .oracle_paths
            .filter(|paths| !paths.is_empty())
            .context("at least one oracle path is required for verify")?;

        if parquet_paths.len() != oracle_paths.len() {
            return Err(anyhow!(
                "number of parquet paths ({}) must match number of oracle paths ({})",
                parquet_paths.len(),
                oracle_paths.len()
            ));
        }

        let proof_path = self
            .proof_path
            .context("proof path is required for verify")?;
        let vk_path = self.vk_path.context("vk-path is required for verify")?;

        Ok(VerifyRunner {
            query,
            parquet_paths,
            oracle_paths,
            proof_path,
            vk_path,
        })
    }
}

pub struct VerifyRunner {
    query: String,
    parquet_paths: Vec<PathBuf>,
    oracle_paths: Vec<PathBuf>,
    proof_path: PathBuf,
    vk_path: PathBuf,
}

impl VerifyRunner {
    pub async fn run(&self) -> Result<()> {
        let ctx = SessionContext::new();
        for parquet_path in &self.parquet_paths {
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

        let tt_proof = TTProof::<B>::load(&self.proof_path)?;
        let tt_vk = TTVk::<B>::load(&self.vk_path)
            .with_context(|| format!("failed to load verifying key {}", self.vk_path.display()))?;
        let arg_verifier = ArgVerifier::new_from_vk(tt_vk.into_inner());

        let oracles: Vec<_> = self
            .oracle_paths
            .iter()
            .map(|path| load_oracle(path))
            .collect::<Result<Vec<_>>>()?;
        let ctx_oracles = ctx_oracles_from_oracles(&self.parquet_paths, &oracles)?;
        let shared_config = build_shared_config(ctx, ctx_oracles);

        let verifier = TTVerifier::new(TTVerifierConfig::default(), shared_config, arg_verifier);
        let prover = ProveBuilder::new()
            .with_query(self.query.clone())
            .with_parquet_paths(self.parquet_paths.clone())
            .with_oracle_paths(self.oracle_paths.clone())
            .build()?
            .build_tt_prover()
            .await?;
        let output_memtable = prover.output_memtable(&self.query).await?;
        verifier
            .verify(&self.query, &tt_proof, output_memtable)
            .await
            .map_err(|err| anyhow!(err))?;

        println!("proof verified successfully");
        Ok(())
    }
}

fn load_oracle(path: &Path) -> Result<ArithTableOracle<B>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open oracle file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    ArithTableOracle::<B>::deserialize_compressed(&mut reader)
        .context("failed to deserialize oracle")
}

fn ctx_oracles_from_oracles(
    parquet_paths: &[PathBuf],
    oracles: &[ArithTableOracle<B>],
) -> Result<CtxOracles<B>> {
    let mut table_oracles = IndexMap::new();
    let mut named_oracles = IndexMap::new();
    for (path, oracle) in parquet_paths.iter().zip(oracles.iter()) {
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow!("oracle does not provide a schema"))?;
        let table_name = path
            .file_stem()
            .ok_or_else(|| anyhow!("parquet {} missing file stem", path.display()))?
            .to_string_lossy()
            .to_string();
        table_oracles.insert(schema, oracle.clone());
        named_oracles.insert(table_name, oracle.clone());
    }
    Ok(CtxOracles::with_named_oracles(table_oracles, named_oracles))
}

fn build_shared_config(
    session_ctx: SessionContext,
    ctx_oracles: CtxOracles<B>,
) -> TTSharedConfig<B> {
    TTSharedConfig::new(
        Analyzer::with_rules(proof_planner::logical_plan_analyzer::rules()),
        Optimizer::with_rules(proof_planner::logical_plan_optimizer::rules(&session_ctx)),
        ctx_oracles,
        session_ctx,
        ConfigOptions::new(),
        OptimizerContext::new(),
        |_plan_after_rule, _rule| {},
    )
}
