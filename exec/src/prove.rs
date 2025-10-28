use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use indexmap::IndexMap;
use proof_planner::create_prover_proof_tree_with_ctx;
use truthtable_core::prover::trees::{
    arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
    piop_tree::ProverPIOPTree, tracked_tree::ProverTrackedTree,
};

use crate::structs::{Artifact, TTPk};

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

pub struct ProveBuilder {
    query: Option<String>,
    parquet_path: Option<PathBuf>,
    oracle_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
}

impl ProveBuilder {
    pub fn new() -> Self {
        Self {
            query: None,
            parquet_path: None,
            oracle_path: None,
            output_path: None,
        }
    }

    pub fn with_query(mut self, query: String) -> Self {
        self.query = Some(query);
        self
    }

    pub fn with_parquet_path(mut self, path: PathBuf) -> Self {
        self.parquet_path = Some(path);
        self
    }

    pub fn with_oracle_path(mut self, path: PathBuf) -> Self {
        self.oracle_path = Some(path);
        self
    }

    pub fn with_output_path(mut self, path: Option<PathBuf>) -> Self {
        self.output_path = path;
        self
    }

    pub fn build(self) -> Result<ProveRunner> {
        let query = self.query.context("query string is required")?;
        let parquet_path = self
            .parquet_path
            .context("parquet path is required for prove")?;
        let oracle_path = self
            .oracle_path
            .context("oracle-path is required for prove")?;

        let output_path = resolve_output_path(self.output_path)?;

        Ok(ProveRunner {
            query,
            parquet_path,
            oracle_path,
            output_path,
        })
    }
}

pub struct ProveRunner {
    query: String,
    parquet_path: PathBuf,
    oracle_path: PathBuf,
    output_path: PathBuf,
}

impl ProveRunner {
    pub async fn run(&self) -> Result<PathBuf> {
        let table_name = self
            .parquet_path
            .file_stem()
            .ok_or_else(|| anyhow!("parquet path must have a file name"))?
            .to_string_lossy()
            .to_string();

        let ctx = SessionContext::new();
        ctx.register_parquet(
            &table_name,
            self.parquet_path
                .to_str()
                .context("parquet path must be valid UTF-8")?,
            ParquetReadOptions::default(),
        )
        .await
        .context("failed to register parquet")?;

        let oracle = load_oracle(&self.oracle_path)?;
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow!("oracle {} missing schema", self.oracle_path.display()))?;
        let mut table_oracles = IndexMap::new();
        table_oracles.insert(schema, oracle.clone());
        let shared_ctx = SharedCtx::new(table_oracles);

        let proof_tree =
            create_prover_proof_tree_with_ctx::<F, MvPCS, UvPCS>(&ctx, &self.query, shared_ctx)
                .await;
        let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
            .await
            .context("failed to build hint tree")?;
        let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree)
            .context("failed to arithmetize")?;

        let pk_path = resolve_pk_path(&self.oracle_path, oracle.log_size())?;

        let tt_pk = TTPk::<F, MvPCS, UvPCS>::load(&pk_path)
            .with_context(|| format!("read proving key {}", pk_path.display()))?;
        let snark_pk = tt_pk.into_inner();
        let mut prover = Prover::<F, MvPCS, UvPCS>::new_from_pk(snark_pk);
        let tracked_tree = ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover)
            .context("failed to build tracked tree")?;
        let mut piop_tree = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);
        let flattened = piop_tree.proof_tree().clone().flatten();
        for node in flattened.values() {
            node.prove_piop(&mut prover, &mut piop_tree)
                .context("prove piop")?;
        }

        let proof = prover.build_proof().context("build proof")?;
        write_proof(&proof, &self.output_path)?;

        Ok(self.output_path.clone())
    }
}

fn load_oracle(path: &Path) -> Result<ArithTableOracle<F, MvPCS, UvPCS>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open oracle file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
        .context("failed to deserialize oracle")
}

fn resolve_pk_path(oracle_path: &Path, log_size: usize) -> Result<PathBuf> {
    const DEFAULT_PK_PREFIX: &str = "tt_proving_key";
    let file_name = format!("{DEFAULT_PK_PREFIX}_{log_size}.pk");

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

fn write_proof(
    proof: &ark_piop::prover::structs::proof::Proof<F, MvPCS, UvPCS>,
    path: &Path,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
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
