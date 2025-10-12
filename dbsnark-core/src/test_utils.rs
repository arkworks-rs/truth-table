use datafusion::{
    error::{Result, Result as DFResult},
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;
pub async fn test_df_plan(
    ctx: &SessionContext,
    query: &str,
    table_name: &str,
) -> DFResult<LogicalPlan> {
    let parquet_path = test_data_path(&format!("{}.parquet", table_name));
    assert!(
        parquet_path.exists(),
        "Missing Parquet at {:?}",
        parquet_path
    );

    ctx.register_parquet(
        table_name,
        parquet_path
            .to_str()
            .expect("parquet path should be valid UTF-8"),
        ParquetReadOptions::default(),
    )
    .await?;

    let df = ctx.sql(&query).await?;
    Ok(df.into_unoptimized_plan())
}
use std::sync::Arc;

use crate::{
    proof_nodes::id::NodeId,
    prover::trees::{
        arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
        piop_tree::ProverPIOPTree, proof_tree::ProverProofTree, tracked_tree::ProverTrackedTree,
    },
    verifier::trees::{
        piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree,
        tracked_tree::VerifierTrackedTree,
    },
};
use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    test_utils::{bench_prelude, init_tracing_for_tests},
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use indexmap::IndexMap;
use tokio::runtime::Runtime;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

pub mod helper {
    use super::*;

    pub fn prove_and_verify_query(sql: &str, table: &str) {
        init_tracing_for_tests();

        let runtime = Runtime::new().expect("create tokio runtime");
        let ctx = SessionContext::new();

        let parquet_path = test_data_path(format!("{table}.parquet"));
        assert!(
            parquet_path.exists(),
            "missing parquet for {table} at {}",
            parquet_path.display()
        );

        runtime.block_on(async {
            ctx.register_parquet(
                table,
                parquet_path
                    .to_str()
                    .expect("parquet path should be valid UTF-8"),
                ParquetReadOptions::default(),
            )
            .await
            .expect("register parquet table");
        });

        let logical_plan = runtime.block_on(async {
            ctx.sql(sql)
                .await
                .unwrap_or_else(|err| panic!("sql execution failed: {err:?}"))
                .into_unoptimized_plan()
        });

        let (mut prover, mut verifier) =
            bench_prelude::<F, MvPCS, UvPCS>().expect("prepare prover and verifier");

        let prover_ctx = SharedCtx::default();
        let proof_tree =
            ProverProofTree::<F, MvPCS, UvPCS>::from_lp(&ctx, prover_ctx.clone(), &logical_plan, &NodeId::None);
        let hint_tree = runtime
            .block_on(ProverHintTree::from_proof_tree(&ctx, proof_tree.clone()))
            .expect("build prover hint tree");
        let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree)
            .expect("build arithmetized tree");
        #[cfg(debug_assertions)]
        for (node_id, tables) in arith_tree.arithmetized_tables() {
            for (label, arith_table) in tables {
                for (field_ref, poly) in arith_table.polynomials() {
                    assert_eq!(
                        poly.num_vars(),
                        arith_table.log_size(),
                        "arithmetized table log size mismatch at node {node_id:?} label {label} field {}",
                        field_ref.name()
                    );
                }
            }
        }
        let arith_snapshot = arith_tree.arithmetized_tables().clone();
        let tracked_tree = ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover)
            .expect("build tracked tree");
        let mut piop_tree = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);

        let prover_nodes = piop_tree.proof_tree().clone().flatten();
        for node in prover_nodes.values() {
            node.prove_piop(&mut prover, &mut piop_tree)
                .expect("prove piop node");
        }
        let mv_param = prover.mv_pcs_prover_param();
        let proof = prover.build_proof().expect("construct proof");

        let mut table_oracle_map = IndexMap::new();
        for (node_id, tables) in arith_snapshot {
            if matches!(node_id, NodeId::LP(LogicalPlan::TableScan(_))) {
                for arith_table in tables.values() {
                    let Some(schema) = arith_table.schema() else {
                        continue;
                    };
                    let mut commitments = IndexMap::new();
                    for (field_ref, poly) in arith_table.polynomials() {
                        let commitment = MvPCS::commit(Arc::clone(&mv_param), poly)
                            .expect("commit table column");
                        commitments.insert(field_ref.clone(), commitment);
                    }
                    let oracle = ArithTableOracle::<F, MvPCS, UvPCS>::new(
                        Some(schema.clone()),
                        commitments,
                        arith_table.log_size(),
                    );
                    table_oracle_map.insert(schema, oracle);
                }
            }
        }
        let verifier_ctx = SharedCtx::new(table_oracle_map);

        verifier.set_proof(proof);
        let verifier_proof_tree =
            VerifierProofTree::from_lp(&ctx, verifier_ctx.clone(), &logical_plan, &NodeId::None);
        let verifier_tracked_tree = VerifierTrackedTree::from_proof_tree(
            verifier_proof_tree.clone(),
            verifier_ctx.clone(),
            &mut verifier,
        );
        let mut verifier_piop_tree =
            VerifierPIOPTree::from_tracked_tree(verifier_tracked_tree, &mut verifier);
        let verifier_nodes = verifier_piop_tree.proof_tree().clone().flatten();
        for node in verifier_nodes.values() {
            node.verify_piop(&mut verifier, &mut verifier_piop_tree)
                .expect("verify piop node");
        }
        verifier.verify().expect("verify proof");
    }
}
