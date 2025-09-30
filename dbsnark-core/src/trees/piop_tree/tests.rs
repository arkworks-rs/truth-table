use super::PIOPTree;
use crate::{
    test_utils::test_df_plan,
    trees::{arithmetized_tree::ArithmetizedTree, hint_tree::HintTree, proof_tree::ProofTree},
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

async fn display_graphviz_for(query: &str, table: &str) -> DFResult<()> {
    let ctx = SessionContext::new();
    let plan = test_df_plan(&ctx, query, table).await?;
    let proof_tree = ProofTree::from_logical_plan(&ctx, &plan);
    let hint_tree = HintTree::from_proof_tree(&ctx, proof_tree).await?;

    let (mut prover, _verifier): (Prover<F, MvPCS, UvPCS>, _) = test_prelude().unwrap();
    let arith_tree = ArithmetizedTree::from_hint_tree(hint_tree, &mut prover).unwrap();
    let piop_plan = PIOPTree::from_arithmetized_plan(arith_tree, &mut prover);

    println!("{}", piop_plan.display_graphviz());
    Ok(())
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz_1() -> DFResult<()> {
    display_graphviz_for(
        "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey",
        "lineitem",
    )
    .await
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz_2() -> DFResult<()> {
    display_graphviz_for(
        "SELECT l_orderkey FROM lineitem WHERE l_quantity >= 20",
        "lineitem",
    )
    .await
}
