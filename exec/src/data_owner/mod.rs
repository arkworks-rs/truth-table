use std::{fs, path::Path};

use anyhow::{Context, Result};
use arithmetic::table::TableComm;
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::test_prelude,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use dbsnark_core::trees::{
    arithmetized_tree::ArithmetizedTree,
    hint_tree::HintTree,
    piop_tree::PIOPTree,
    proof_tree::{ProofTree, nodes::ProverNodeNodeId},
};
use tokio::runtime::Runtime;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

/// Commit the contents of a parquet file by materializing the table-scanned
/// witness and storing it next to the parquet file. The output is a debug
/// representation of the `ArithTable` associated with the table scan node.
pub fn commit_parquet(parquet_path: &Path) -> Result<()> {
    let parquet_path = parquet_path.to_path_buf();
    let parquet_path_for_async = parquet_path.clone();
    let table_name = parquet_path
        .file_stem()
        .context("parquet path must have a file name")?
        .to_string_lossy()
        .to_string();

    let rt = Runtime::new().context("failed to create tokio runtime")?;
    let serialized: Vec<u8> = rt.block_on(async move {
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
            test_prelude::<F, MvPCS, UvPCS>().context("failed to prepare prover")?;

        let proof_tree = ProofTree::<F, MvPCS, UvPCS>::from_logical_plan(&ctx, &logical_plan);
        let hint_tree = HintTree::from_proof_tree(&ctx, proof_tree)
            .await
            .context("failed to build hint tree")?;
        let arith_tree =
            ArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree, &mut prover)
                .context("failed to arithmetize")?;

        let mut piop_tree = PIOPTree::from_arithmetized_plan(arith_tree, &mut prover);
        let flattened = piop_tree.proof_tree().clone().flatten();
        for node in flattened.values() {
            node.prove_piop(&mut prover, &mut piop_tree)
                .context("prove piop")?;
        }
        let proof = prover.build_proof().context("build proof")?;
        verifier.set_proof(proof);

        let (_, tables_by_node) = piop_tree.into_parts();

        let mut table_comm: Option<TableComm<F, MvPCS, UvPCS>> = None;
        for (node_id, tables) in &tables_by_node {
            if let ProverNodeNodeId::LP(plan) = node_id {
                if matches!(plan, datafusion::logical_expr::LogicalPlan::TableScan(_)) {
                    if let Some(table) = tables.get("output_plan") {
                        table_comm = Some(TableComm::from(table.clone(), &mut verifier)?);
                        break;
                    }
                }
            }
        }

        let table_comm = table_comm.context("table scan result not found")?;
        let bytes = bincode::serialize(&table_comm).context("serialize table commitment")?;
        Ok::<Vec<u8>, anyhow::Error>(bytes)
    })?;

    let mut output_path = parquet_path;
    output_path.set_extension("table.bin");
    fs::write(&output_path, serialized).context("failed to write committed table")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpch_data::test_data_path;

    #[test]
    fn commit_parquet_smoke() {
        let parquet_path = test_data_path("nation.parquet");
        assert!(parquet_path.exists());

        commit_parquet(&parquet_path).expect("commit nation parquet");

        let output_path = parquet_path.with_extension("table.bin");
        assert!(output_path.exists());
        // let _ = fs::remove_file(output_path);
    }
}
