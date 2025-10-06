use std::{collections::HashMap, hash::Hash};

use crate::test_utils::test_df_plan;

use super::ProverProofTree;
use arithmetic::ctx::SharedCtx;
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::init_tracing_for_tests,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    error::Result as DFResult,
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz() {
    init_tracing_for_tests();
    let ctx = SessionContext::new();
    let plan = test_df_plan(
        &ctx,
        r#"
SELECT count(l_partkey) FROM lineitem GROUP BY l_quantity
        "#,
        "lineitem",
    )
    .await
    .unwrap();
    let prover_ctx = SharedCtx::default();
    let proof_tree: ProverProofTree<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> =
        ProverProofTree::from_lp(&ctx, prover_ctx, &plan);
    println!("{}", proof_tree.display_graphviz());
}
