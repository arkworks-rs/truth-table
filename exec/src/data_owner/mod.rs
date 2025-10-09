use std::{
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use arithmetic::{
    ctx::SharedCtx,
    table_oracle::{ArithTableOracle, TrackedTableOracle},
};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::{bench_prelude, test_prelude},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use dbsnark_core::{
    proof_nodes::id::NodeId,
    prover::trees::{
        arithmetized_tree::ProverArithmetizedTree,
        hint_tree::ProverHintTree,
        piop_tree::ProverPIOPTree,
        proof_tree::ProverProofTree,
        tracked_tree::{self, ProverTrackedTree},
    },
};
use tokio::runtime::Runtime;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

/// Commit the contents of a parquet file by materializing the table-scanned
/// witness, producing the verifier-side oracle table, serializing it, and
/// returning its serializable form together with the path where it was stored.
pub fn commit_parquet(parquet_path: &Path) -> Result<(ArithTableOracle<F, MvPCS, UvPCS>, PathBuf)> {
    let parquet_path = parquet_path.to_path_buf();
    let parquet_path_for_async = parquet_path.clone();
    let table_name = parquet_path
        .file_stem()
        .context("parquet path must have a file name")?
        .to_string_lossy()
        .to_string();

    let rt = Runtime::new().context("failed to create tokio runtime")?;
    rt.block_on(async move {
        let parquet_path = parquet_path_for_async;
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

        let logical_plan = ctx
            .table(&table_name)
            .await
            .context("failed to build logical plan")?
            .into_unoptimized_plan();

        let (mut prover, mut verifier) =
            bench_prelude::<F, MvPCS, UvPCS>().context("failed to prepare prover")?;
        let prover_ctx = SharedCtx::default();
        let proof_tree =
            ProverProofTree::<F, MvPCS, UvPCS>::from_lp(&ctx, prover_ctx, &logical_plan);
        let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
            .await
            .context("failed to build hint tree")?;
        let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree)
            .context("failed to arithmetize")?;
        let tracked_tree =
            ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover).unwrap();
        let mut piop_tree = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);
        let flattened = piop_tree.proof_tree().clone().flatten();
        for node in flattened.values() {
            node.prove_piop(&mut prover, &mut piop_tree)
                .context("prove piop")?;
        }
        let proof = prover.build_proof().context("build proof")?;
        verifier.set_proof(proof);

        let (_, tables_by_node) = piop_tree.into_parts();

        let mut tracked_Table_oracle: Option<TrackedTableOracle<F, MvPCS, UvPCS>> = None;
        for (node_id, tables) in &tables_by_node {
            if let NodeId::LP(plan) = node_id {
                if matches!(plan, datafusion::logical_expr::LogicalPlan::TableScan(_)) {
                    if let Some(table) = tables.get("output_plan") {
                        tracked_Table_oracle = Some(TrackedTableOracle::from_tracked_table(
                            table.clone(),
                            &mut verifier,
                        )?);
                        break;
                    }
                }
            }
        }

        let tracked_Table_oracle = tracked_Table_oracle.context("table scan result not found")?;

        let serializable = ArithTableOracle::from_tracked_table_oracle(&tracked_Table_oracle);

        let output_path = parquet_path.with_extension("oracle");
        let file = File::create(&output_path).with_context(|| {
            format!(
                "failed to create serialized oracle file at {}",
                output_path.display()
            )
        })?;
        let mut writer = BufWriter::new(file);
        serializable
            .serialize_uncompressed(&mut writer)
            .context("failed to serialize oracle")?;
        writer
            .flush()
            .context("failed to flush serialized oracle to disk")?;

        Ok((serializable, output_path))
    })
}

/// Load a previously committed parquet table from disk.
pub fn load_parquet_commitment(
    commitment_path: &Path,
) -> Result<ArithTableOracle<F, MvPCS, UvPCS>> {
    let file = File::open(commitment_path).with_context(|| {
        format!(
            "failed to open serialized oracle file at {}",
            commitment_path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
        .context("failed to deserialize oracle")
}

/// Commit a parquet file and verify the resulting oracle can be deserialized
/// back.
pub fn commit_parquet_serializes_oracle(parquet_path: &Path) -> Result<()> {
    let (serializable, serialized_path) =
        commit_parquet(parquet_path).context("failed to commit parquet")?;

    let reloaded = load_parquet_commitment(&serialized_path).context("failed to reload oracle")?;

    if serializable.schema() != reloaded.schema() {
        anyhow::bail!("reloaded oracle schema does not match original");
    }

    let mut original_bytes = Vec::new();
    serializable
        .serialize_uncompressed(&mut original_bytes)
        .context("failed to serialize original oracle")?;

    let mut reloaded_bytes = Vec::new();
    reloaded
        .serialize_uncompressed(&mut reloaded_bytes)
        .context("failed to serialize reloaded oracle")?;

    if original_bytes != reloaded_bytes {
        anyhow::bail!("reloaded oracle bytes differ from original");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::commit_parquet_serializes_oracle;
    use tpch_data::{bench_data_path, test_data_path};

    #[test]
    #[ignore = "Takes too long"]
    fn commit_parquet_serializes_oracle_round_trip() {
        let parquet_path = bench_data_path("lineitem.parquet");
        assert!(parquet_path.exists());

        commit_parquet_serializes_oracle(&parquet_path)
            .expect("commit and verify lineitem parquet oracle");
    }
}
