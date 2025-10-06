use super::ProverArithmetizedTree;
use crate::{
    prover::trees::{hint_tree::ProverHintTree, proof_tree::ProverProofTree},
    test_utils::test_df_plan,
};
use arithmetic::ctx::SharedCtx;
use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::SessionContext;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

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
    //     "SELECT count(l_partkey) FROM lineitem GROUP BY 2*l_quantity",
    // )
    // .await;
}

async fn display_graphviz_for(table: &str, query: &str) {
    let ctx = SessionContext::new();
    let plan = test_df_plan(&ctx, query, table).await.unwrap();
    let prover_ctx = SharedCtx::default();
    let proof_tree: ProverProofTree<F, MvPCS, UvPCS> =
        ProverProofTree::from_lp(&ctx, prover_ctx, &plan);
    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
        .await
        .unwrap();
    let arith_tree = ProverArithmetizedTree::from_hint_tree(hint_tree).unwrap();
    println!(
        "The ordered list of nodes {:?}\n",
        arith_tree
            .arithmetized_tables()
            .keys()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
    );
    println!("{}", arith_tree.display_graphviz());
}
