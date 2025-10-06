use crate::{test_utils::test_df_plan, verifier::trees::proof_tree::VerifierProofTree};
use arithmetic::ctx::SharedCtx;
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
    let verifier_ctx = SharedCtx::default();
    let proof_tree: VerifierProofTree<Fr, PST13<Bls12_381>, KZG10<Bls12_381>> =
        VerifierProofTree::from_lp(&ctx, verifier_ctx, &plan);
    println!("{}", proof_tree.display_graphviz());
}
