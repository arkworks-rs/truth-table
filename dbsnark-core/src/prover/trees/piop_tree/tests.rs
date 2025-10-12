use super::ProverPIOPTree;
use crate::{
    proof_nodes::id::NodeId, prover::trees::{
        arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
        proof_tree::ProverProofTree, tracked_tree::ProverTrackedTree,
    }, test_utils::test_df_plan
};
use arithmetic::ctx::SharedCtx;
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    test_utils::test_prelude,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{error::Result as DFResult, prelude::SessionContext};

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

async fn display_graphviz_for(query: &str, table: &str) -> DFResult<()> {
    let ctx = SessionContext::new();
    let plan = test_df_plan(&ctx, query, table).await?;
    let prover_ctx = SharedCtx::default();
    let proof_tree = ProverProofTree::from_lp(&ctx, prover_ctx, &plan, &NodeId::None);
    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree).await?;
    let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree).unwrap();
    let (mut prover, _verifier): (Prover<F, MvPCS, UvPCS>, _) = test_prelude().unwrap();
    let tracked_tree = ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover).unwrap();
    let piop_plan = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);
    println!(
        "The ordered list of nodes {:?}\n",
        piop_plan
            .tracked_tables()
            .keys()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
    );
    println!("{}", piop_plan.display_graphviz());

    Ok(())
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz_piop_tree_1() -> DFResult<()> {
    display_graphviz_for(
        "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey",
        "lineitem",
    )
    .await
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz_piop_tree_2() -> DFResult<()> {
    display_graphviz_for(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey+20 > l_partkey*2-l_orderkey",
        "lineitem",
    )
    .await
}
