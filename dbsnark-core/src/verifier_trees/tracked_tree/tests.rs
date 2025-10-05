use crate::{
    test_utils::test_df_plan,
    verifier_trees::{proof_tree::VerifierProofTree, tracked_tree::VerifierTrackedTree},
};
use arithmetic::ctx::SharedCtx;
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::test_prelude,
    verifier::Verifier,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::SessionContext;

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
    let prover_ctx = SharedCtx::default();
    let proof_tree = VerifierProofTree::from_lp(&ctx, prover_ctx, &plan);
    let (_prover, mut verifier): (_, Verifier<F, MvPCS, UvPCS>) = test_prelude().unwrap();
    let tracked_tree = VerifierTrackedTree::from_proof_tree(proof_tree, &mut verifier);

    println!("{}", tracked_tree.display_graphviz());
}
