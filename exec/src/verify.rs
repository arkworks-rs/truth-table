use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    verifier::Verifier,
};
use ark_serialize::CanonicalDeserialize;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use indexmap::IndexMap;
use proof_planner::create_verifier_proof_tree_with_ctx;
use truthtable_core::verifier::trees::{
    piop_tree::{VerifierPIOPTree, display::DisplayableVerifierPIOPTree},
    tracked_tree::VerifierTrackedTree,
};

use crate::structs::{Artifact, TTVk};

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;
type Proof = ark_piop::prover::structs::proof::Proof<F, MvPCS, UvPCS>;

pub struct VerifyBuilder {
    query: Option<String>,
    parquet_paths: Option<Vec<PathBuf>>,
    oracle_paths: Option<Vec<PathBuf>>,
    proof_path: Option<PathBuf>,
    vk_path: Option<PathBuf>,
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

        let oracles: Vec<_> = self
            .oracle_paths
            .iter()
            .map(|path| load_oracle(path))
            .collect::<Result<Vec<_>>>()?;
        let shared_ctx = shared_ctx_from_oracles(&oracles)?;

        let verifier_proof_tree =
            create_verifier_proof_tree_with_ctx::<F, MvPCS, UvPCS>(&ctx, &self.query, shared_ctx)
                .await;

        let proof = load_proof(&self.proof_path)?;
        let tt_vk = TTVk::<F, MvPCS, UvPCS>::load(&self.vk_path)
            .with_context(|| format!("failed to load verifying key {}", self.vk_path.display()))?;
        let snark_vk = tt_vk.into_inner();
        let mut verifier = Verifier::<F, MvPCS, UvPCS>::new_from_vk(snark_vk);
        verifier.set_proof(proof);

        let verifier_tracked_tree =
            VerifierTrackedTree::from_proof_tree(verifier_proof_tree, &mut verifier);

        let mut verifier_piop_tree =
            VerifierPIOPTree::from_tracked_tree(verifier_tracked_tree, &mut verifier);
        verifier_piop_tree
            .verify(&mut verifier)
            .context("verify piop tree")?;

        match verifier.verify() {
            Ok(()) => {
                println!("\x1b[32mproof verified successfully\x1b[0m");
                Ok(())
            },
            Err(err) => {
                eprintln!("\x1b[31mproof verification failed: {err}\x1b[0m");
                Err(anyhow!(err))
            },
        }
    }
}

fn load_oracle(path: &Path) -> Result<ArithTableOracle<F, MvPCS, UvPCS>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open oracle file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
        .context("failed to deserialize oracle")
}

fn load_proof(path: &Path) -> Result<Proof> {
    let file = File::open(path)
        .with_context(|| format!("failed to open proof file {}", path.display()))?;
    let mut reader = BufReader::new(file);
    Proof::deserialize_uncompressed(&mut reader).context("failed to deserialize proof")
}

fn shared_ctx_from_oracles(
    oracles: &[ArithTableOracle<F, MvPCS, UvPCS>],
) -> Result<SharedCtx<F, MvPCS, UvPCS>> {
    let mut table_oracles = IndexMap::new();
    for oracle in oracles {
        let schema = oracle
            .schema()
            .ok_or_else(|| anyhow!("oracle does not provide a schema"))?;
        table_oracles.insert(schema, oracle.clone());
    }
    Ok(SharedCtx::new(table_oracles))
}
