use std::collections::HashMap;

use super::ProverHintTree;
use crate::{prover_trees::proof_tree::ProverProofTree, test_utils::test_df_plan};
use arithmetic::ctx::ProverCtx;
use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::SessionContext;

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz() {
    let ctx = SessionContext::new();
    let plan = test_df_plan(
        &ctx,
        "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey",
        "lineitem",
    )
    .await
    .unwrap();
    let prover_ctx = ProverCtx::default();
    let proof_tree: ProverProofTree<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> =
        ProverProofTree::from_lp(&ctx, prover_ctx, &plan);
    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
        .await
        .unwrap();
    println!("{}", hint_tree.display_graphviz());
}
