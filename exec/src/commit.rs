use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use arithmetic::table_oracle::{ArithTableOracle, TrackedTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    setup::structs::SNARKVk,
    verifier::Verifier,
};
use ark_serialize::CanonicalSerialize;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use proof_planner::create_prover_proof_tree;
use truthtable_core::{
    proof_nodes::{OUTPUT_PLAN_KEY, id::NodeId},
    prover::trees::{
        arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
        piop_tree::ProverPIOPTree, tracked_tree::ProverTrackedTree,
    },
};

use crate::structs::{Artifact, TTPk};

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

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
        },
        None => {
            let base =
                std::env::current_dir().context("failed to resolve current working directory")?;
            Ok(base.join(default_name))
        },
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

    let query = format!("SELECT * FROM {table_name}");

    let proof_tree = create_prover_proof_tree::<F, MvPCS, UvPCS>(&ctx, &query).await;
    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
        .await
        .context("failed to build hint tree")?;
    let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree)
        .context("failed to arithmetize")?;

    let (mut prover, mut verifier) = load_prover_verifier(pk_path)
        .with_context(|| format!("failed to load proving key from {}", pk_path.display()))?;
    let tracked_tree = ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover)
        .context("failed to build tracked tree")?;
    let mut piop_tree = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);
    piop_tree.prove(&mut prover).context("prove piop tree")?;

    let proof = prover.build_proof().context("build proof")?;
    verifier.set_proof(proof);

    let (_, tables_by_node) = piop_tree.into_parts();

    let mut tracked_table_oracle: Option<TrackedTableOracle<F, MvPCS, UvPCS>> = None;
    for (node_id, tables) in &tables_by_node {
        if let NodeId::LP(plan) = node_id
            && matches!(plan, datafusion::logical_expr::LogicalPlan::TableScan(_))
            && let Some(table) = tables.get(OUTPUT_PLAN_KEY)
        {
            tracked_table_oracle = Some(TrackedTableOracle::from_tracked_table(
                table.clone(),
                &mut verifier,
            )?);
            break;
        }
    }

    let tracked_table_oracle =
        tracked_table_oracle.context("table scan result not found in proof tree")?;
    let serializable = ArithTableOracle::from_tracked_table_oracle(&tracked_table_oracle);

    write_oracle(&serializable, output_path)?;

    Ok(output_path.to_path_buf())
}

fn load_prover_verifier(
    pk_path: &Path,
) -> Result<(Prover<F, MvPCS, UvPCS>, Verifier<F, MvPCS, UvPCS>)> {
    let tt_pk = TTPk::<F, MvPCS, UvPCS>::load(pk_path)
        .with_context(|| format!("load {}", pk_path.display()))?;
    let snark_pk = tt_pk.into_inner();
    let vk: SNARKVk<F, MvPCS, UvPCS> = snark_pk.vk.clone();
    let prover = Prover::<F, MvPCS, UvPCS>::new_from_pk(snark_pk);
    let verifier = Verifier::<F, MvPCS, UvPCS>::new_from_vk(vk);
    Ok((prover, verifier))
}

fn write_oracle(
    serializable: &ArithTableOracle<F, MvPCS, UvPCS>,
    output_path: &Path,
) -> Result<()> {
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
