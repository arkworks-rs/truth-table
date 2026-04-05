use anyhow::{Context, Result, anyhow};
use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::{DefaultSnarkBackend, verifier::ArgVerifier};
use ark_serialize::CanonicalDeserialize;
use datafusion::{
    config::ConfigOptions,
    datasource::MemTable,
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
    sync::Arc,
};
use tt_core::ctx_oracles::CtxOracles;

type B = DefaultSnarkBackend;

pub struct VerifyBuilder {
    query: Option<String>,
    oracle_paths: Option<Vec<PathBuf>>,
    proof_path: Option<PathBuf>,
    result_path: Option<PathBuf>,
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
            oracle_paths: None,
            proof_path: None,
            result_path: None,
            vk_path: None,
        }
    }

    pub fn with_query(mut self, query: String) -> Self {
        self.query = Some(query);
        self
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

    pub fn with_result_path(mut self, path: PathBuf) -> Self {
        self.result_path = Some(path);
        self
    }

    pub fn with_vk_path(mut self, path: PathBuf) -> Self {
        self.vk_path = Some(path);
        self
    }

    pub fn build(self) -> Result<VerifyRunner> {
        let query = self.query.context("query string is required")?;
        let oracle_paths = self
            .oracle_paths
            .filter(|paths| !paths.is_empty())
            .context("at least one oracle path is required for verify")?;

        let proof_path = self
            .proof_path
            .context("proof path is required for verify")?;
        let result_path = self
            .result_path
            .context("result path is required for verify")?;
        let vk_path = self.vk_path.context("vk-path is required for verify")?;

        Ok(VerifyRunner {
            query,
            oracle_paths,
            proof_path,
            result_path,
            vk_path,
        })
    }
}

pub struct VerifyRunner {
    query: String,
    oracle_paths: Vec<PathBuf>,
    proof_path: PathBuf,
    result_path: PathBuf,
    vk_path: PathBuf,
}

impl VerifyRunner {
    pub async fn run(&self) -> Result<()> {
        let tt_proof = TTProof::<B>::load(&self.proof_path)?;
        let tt_vk = TTVk::<B>::load(&self.vk_path)
            .with_context(|| format!("failed to load verifying key {}", self.vk_path.display()))?;
        let arg_verifier = ArgVerifier::new_from_vk(tt_vk.into_inner());

        let oracles: Vec<_> = self
            .oracle_paths
            .iter()
            .map(|path| load_oracle(path))
            .collect::<Result<Vec<_>>>()?;
        let ctx = session_ctx_from_oracles(&oracles)?;
        let ctx_oracles = ctx_oracles_from_oracles(&oracles)?;
        let shared_config = build_shared_config(ctx, ctx_oracles);

        let verifier = TTVerifier::new(TTVerifierConfig::default(), shared_config, arg_verifier);
        let output_memtable = load_result_memtable(&self.result_path).await?;
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

async fn load_result_memtable(path: &Path) -> Result<Arc<MemTable>> {
    if !path.exists() {
        return Err(anyhow!("result parquet file not found: {}", path.display()));
    }
    if !path.is_file() {
        return Err(anyhow!(
            "result parquet path is not a file: {}",
            path.display()
        ));
    }

    let ctx = SessionContext::new();
    let df = ctx
        .read_parquet(
            path.to_str()
                .context("result parquet path must be valid UTF-8")?,
            ParquetReadOptions::default(),
        )
        .await
        .with_context(|| format!("failed to read result parquet {}", path.display()))?;
    let logical_schema = df.schema().as_arrow().clone();
    let batches = df
        .collect()
        .await
        .with_context(|| format!("failed to collect result parquet {}", path.display()))?;
    let schema = batches
        .first()
        .map(|batch| batch.schema())
        .unwrap_or_else(|| Arc::new(logical_schema));
    let mem_table = MemTable::try_new(schema, vec![batches])
        .context("failed to rebuild output memtable from result parquet")?;
    Ok(Arc::new(mem_table))
}

fn ctx_oracles_from_oracles(oracles: &[ArithTableOracle<B>]) -> Result<CtxOracles<B>> {
    let mut table_oracles = IndexMap::new();
    for oracle in oracles {
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow!("oracle does not provide a schema"))?;
        table_oracles.insert(schema, oracle.clone());
    }
    Ok(CtxOracles::new(table_oracles))
}

fn session_ctx_from_oracles(oracles: &[ArithTableOracle<B>]) -> Result<SessionContext> {
    let ctx = SessionContext::new();

    for oracle in oracles {
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow!("oracle does not provide a schema"))?;
        let table_name = infer_table_name_from_schema(&schema).ok_or_else(|| {
            anyhow!("oracle schema is missing table qualifier metadata needed for planning")
        })?;
        let mem_table = MemTable::try_new(Arc::new(schema), vec![vec![]])
            .context("failed to build schema-only memtable from oracle")?;
        ctx.register_table(table_name, Arc::new(mem_table))
            .context("failed to register schema-only oracle table")?;
    }

    Ok(ctx)
}

fn infer_table_name_from_schema(schema: &datafusion::arrow::datatypes::Schema) -> Option<String> {
    schema.fields().iter().find_map(|field| {
        if field.name() == arithmetic::ACTIVATOR_COL_NAME
            || field.name() == arithmetic::ROW_ID_COL_NAME
        {
            return None;
        }
        field.metadata().get("tt.qualifier").map(|qualifier| {
            qualifier
                .rsplit('.')
                .next()
                .unwrap_or(qualifier)
                .to_string()
        })
    })
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
