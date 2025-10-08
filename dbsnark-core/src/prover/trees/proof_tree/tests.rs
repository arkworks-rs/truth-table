use std::{ hash::Hash};

use crate::test_utils::test_df_plan;

use super::ProverProofTree;
use arithmetic::ctx::SharedCtx;
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::init_tracing_for_tests,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::SessionContext;

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz() {
    display_graphviz_for(
        "lineitem",
        "SELECT l_suppkey+l_partkey, l_extendedprice FROM lineitem where l_quantity+l_linenumber == 5 ",
    )
    .await;
    // display_graphviz_for(
    //     "lineitem",
    //     "SELECT count(l_partkey) FROM lineitem GROUP BY l_quantity",
    // )
    // .await;
}

async fn display_graphviz_for(table: &str, query: &str) {
    init_tracing_for_tests();
    let ctx = SessionContext::new();
    let plan = test_df_plan(&ctx, query, table).await.unwrap();
    let prover_ctx = SharedCtx::default();
    let proof_tree: ProverProofTree<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> =
        ProverProofTree::from_lp(&ctx, prover_ctx, &plan);
    println!("{}", proof_tree.display_graphviz());
}
