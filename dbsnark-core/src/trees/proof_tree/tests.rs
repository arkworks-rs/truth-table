use crate::{proof_tree, test_utils::test_df_plan};

use super::ProofTree;
use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
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
    let ctx = SessionContext::new();
    let plan = test_df_plan(
        &ctx,
        "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey",
        "lineitem",
    )
    .await
    .unwrap();
    let proof_tree: ProofTree<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> =
        ProofTree::from_logical_plan(&ctx, &plan);
    println!("{}", proof_tree.display_graphviz());
}
