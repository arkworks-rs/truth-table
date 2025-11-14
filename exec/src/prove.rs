use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    setup::structs::SNARKPk,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use indexmap::IndexMap;
use proof_planner::create_prover_proof_tree_with_ctx;
use tracing::instrument;
use truthtable_core::prover::trees::{
    arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
    piop_tree::ProverPIOPTree, tracked_tree::ProverTrackedTree,
};

use crate::{
    runtime,
    structs::{Artifact, TTPk},
};

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

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
    arith_tree: ProverArithmetizedTree<F, MvPCS, UvPCS>,
    snark_pk: SNARKPk<F, MvPCS, UvPCS>,
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
        let proof = build_proof_from_artifacts(artifacts);
        let elapsed = start.elapsed();
        let proof = proof
            .with_context(|| format!("build_proof_from_artifacts failed after {:.2?}", elapsed))?;
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
    let mut table_oracles = IndexMap::new();

    for (parquet_path, oracle_path) in parquet_paths.iter().zip(oracle_paths.iter()) {
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

        let oracle = load_oracle(oracle_path)?;
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow!("oracle {} missing schema", oracle_path.display()))?;

        table_oracles.insert(schema, oracle.clone());
    }

    let shared_ctx = SharedCtx::new(table_oracles);

    let proof_tree =
        create_prover_proof_tree_with_ctx::<F, MvPCS, UvPCS>(&ctx, query, shared_ctx).await;

    println!("{}", proof_tree.display_graphviz());

    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
        .await
        .context("failed to build hint tree")?;

    println!("{}", hint_tree.display_graphviz());
    let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree)
        .context("failed to arithmetize")?;

    let pk_path = match pk_path {
        Some(path) => path.to_path_buf(),
        None => {
            let oracle_path = oracle_paths
                .first()
                .ok_or_else(|| anyhow!("at least one oracle path is required for prove"))?;
            resolve_pk_path(oracle_path)?
        },
    };
    let tt_pk = TTPk::<F, MvPCS, UvPCS>::load(&pk_path)
        .with_context(|| format!("read proving key {}", pk_path.display()))?;
    let snark_pk = tt_pk.into_inner();
    Ok(PreparedProverArtifacts {
        arith_tree,
        snark_pk,
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
    fn into_parts(
        self,
    ) -> (
        ProverArithmetizedTree<F, MvPCS, UvPCS>,
        SNARKPk<F, MvPCS, UvPCS>,
    ) {
        (self.arith_tree, self.snark_pk)
    }
}

#[instrument(level = "debug", skip_all)]
pub fn build_proof_from_artifacts(
    artifacts: PreparedProverArtifacts,
) -> Result<ark_piop::prover::structs::proof::Proof<F, MvPCS, UvPCS>> {
    let (arith_tree, snark_pk) = artifacts.into_parts();
    let mut prover = Prover::<F, MvPCS, UvPCS>::new_from_pk(snark_pk);
    let tracked_tree = ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover)
        .context("failed to build tracked tree")?;
    let mut piop_tree = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);
    piop_tree.prove(&mut prover).context("prove piop tree")?;

    prover.build_proof().context("build proof")
}

#[instrument(level = "debug", skip_all)]
fn load_oracle(path: &Path) -> Result<ArithTableOracle<F, MvPCS, UvPCS>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open oracle file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed_unchecked(&mut reader)
        .context("failed to deserialize oracle")
}

#[instrument(level = "debug", skip_all)]
fn resolve_pk_path(oracle_path: &Path) -> Result<PathBuf> {
    const DEFAULT_PK_PREFIX: &str = "tt_proving_key";
    let file_name = format!("{DEFAULT_PK_PREFIX}_16.pk");

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
        },
        None => Ok(std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join(DEFAULT_PROOF_FILE)),
    }
}
#[instrument(level = "debug", skip_all)]
fn write_proof(
    proof: &ark_piop::prover::structs::proof::Proof<F, MvPCS, UvPCS>,
    path: &Path,
) -> Result<()> {
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
        .serialize_uncompressed(&mut writer)
        .context("failed to serialize proof")?;
    writer
        .flush()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    Ok(())
}
