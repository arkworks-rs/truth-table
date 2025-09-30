use super::ArithmetizedTree;
use crate::{
    test_utils::test_df_plan,
    trees::{hint_tree::HintTree, proof_tree::ProofTree},
};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    test_utils::test_prelude,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    error::Result as DFResult,
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;
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
    let proof_tree = ProofTree::from_logical_plan(&ctx, &plan);
    let hint_tree = HintTree::from_proof_tree(&ctx, proof_tree).await.unwrap();
    let (mut prover, _verifier): (Prover<F, MvPCS, UvPCS>, _) = test_prelude().unwrap();
    let arith_tree = ArithmetizedTree::from_hint_tree(hint_tree, &mut prover).unwrap();

    println!("{}", arith_tree.display_graphviz());
}
