use arithmetic::ACTIVATOR_COL_NAME;
use datafusion::{
    common::Column,
    error::{Result, Result as DFResult},
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder, Operator},
    optimizer::{Optimizer, OptimizerContext, OptimizerRule},
    prelude::{ParquetReadOptions, SessionContext},
    scalar::ScalarValue,
};
use datafusion_expr::expr::BinaryExpr as DFBinaryExpr;
use tpch_data::test_data_path;
pub async fn test_df_plan(
    ctx: &SessionContext,
    query: &str,
    table_names: &[&str],
) -> DFResult<LogicalPlan> {
    for &table_name in table_names {
        let parquet_path = test_data_path(&format!("{table_name}.parquet"));
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
    }
    let state = ctx.state();
    let mut plan = state.create_logical_plan(query).await?;
    let rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = vec![];

    let optimizer = Optimizer::with_rules(rules);

    let config = OptimizerContext::new().with_max_passes(16);

    let plan = optimizer.optimize(plan.clone(), &config, observer)?;

    fn observer(plan: &LogicalPlan, rule: &dyn OptimizerRule) {
        println!(
            "After applying rule '{}':\n{}",
            rule.name(),
            plan.display_indent()
        )
    }
    Ok(plan)
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

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

pub mod helper {
    use super::*;

    pub async fn prove_and_verify_query(
        ctx: &SessionContext,
        proof_tree: ProverProofTree<F, MvPCS, UvPCS>,
        verifier_proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
    ) {
        init_tracing_for_tests();
        let (mut prover, mut verifier) =
            bench_prelude::<F, MvPCS, UvPCS>().expect("prepare prover and verifier");

        let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree.clone())
            .await
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

        piop_tree.prove(&mut prover).expect("prove piop tree");
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
        let verifier_tracked_tree = VerifierTrackedTree::from_proof_tree(
            verifier_proof_tree.clone(),
            verifier_ctx.clone(),
            &mut verifier,
        );
        let mut verifier_piop_tree =
            VerifierPIOPTree::from_tracked_tree(verifier_tracked_tree, &mut verifier);
        verifier_piop_tree
            .verify(&mut verifier)
            .expect("verify piop tree");
        verifier.verify().expect("verify proof");
    }
}
