use super::HintTree;
use crate::{test_utils::test_df_plan, trees::proof_tree::ProofTree};
use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::SessionContext;

#[tokio::test]
#[ignore]
async fn display_graphviz() {
    let ctx = SessionContext::new();
    let plan = test_df_plan(&ctx).await.unwrap();
    let proof_tree: ProofTree<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> =
        ProofTree::from_logical_plan(&ctx, &plan);
    let hint_tree = HintTree::from_proof_tree(&ctx, proof_tree).await.unwrap();
    println!("{}", hint_tree.display_graphviz());
}
