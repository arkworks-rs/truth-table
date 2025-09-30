use std::{
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use arithmetic::table_oracle::{ArithTableOracle, SerializableArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::test_prelude,
};
use ark_serialize::CanonicalSerialize;
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
/// witness, producing the verifier-side oracle table, serializing it, and
/// returning its serializable form together with the path where it was stored.
pub fn commit_parquet(
    parquet_path: &Path,
) -> Result<(SerializableArithTableOracle<F, MvPCS, UvPCS>, PathBuf)> {
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

        let mut arith_table_oracle: Option<ArithTableOracle<F, MvPCS, UvPCS>> = None;
        for (node_id, tables) in &tables_by_node {
            if let ProverNodeNodeId::LP(plan) = node_id {
                if matches!(plan, datafusion::logical_expr::LogicalPlan::TableScan(_)) {
                    if let Some(table) = tables.get("output_plan") {
                        arith_table_oracle =
                            Some(ArithTableOracle::from(table.clone(), &mut verifier)?);
                        break;
                    }
                }
            }
        }

        let arith_table_oracle = arith_table_oracle.context("table scan result not found")?;

        let serializable =
            SerializableArithTableOracle::from_arith_table_oracle(&arith_table_oracle);

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

#[cfg(test)]
mod tests {
    use super::*;
    use arithmetic::table_oracle::SerializableArithTableOracle;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use std::{fs, io::Cursor};
    use tpch_data::test_data_path;

    #[test]
    fn commit_parquet_serializes_oracle() {
        let parquet_path = test_data_path("nation.parquet");
        assert!(parquet_path.exists());

        let (serializable, serialized_path) =
            commit_parquet(&parquet_path).expect("commit nation parquet");

        assert!(serialized_path.exists());

        let mut expected_bytes = Vec::new();
        serializable
            .serialize_uncompressed(&mut expected_bytes)
            .expect("serialize oracle to bytes");

        let file_bytes = fs::read(&serialized_path).expect("read serialized oracle file");
        assert_eq!(expected_bytes, file_bytes);

        let mut reader = Cursor::new(file_bytes.as_slice());
        let deserialized =
            SerializableArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
                .expect("deserialize oracle from file");

        assert_eq!(serializable.schema(), deserialized.schema());

        let mut round_trip_bytes = Vec::new();
        deserialized
            .serialize_uncompressed(&mut round_trip_bytes)
            .expect("serialize deserialized oracle");
        assert_eq!(expected_bytes, round_trip_bytes);
    }
}
