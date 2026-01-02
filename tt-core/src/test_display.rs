use crate::prover::trees::{
    arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
    piop_tree::ProverPIOPTree, proof_tree::ProverProofTree, tracked_tree::ProverTrackedTree,
};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    test_utils::{init_tracing_for_tests, test_prelude},
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::SessionContext;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

pub async fn display_prover_proof_tree(proof_tree: &ProverProofTree<B>) {
    init_tracing_for_tests();
    proof_tree
        .arena()
        .values()
        .for_each(|v| println!("{}", v.name()));
    println!("--------------------------------");
    println!("{}", proof_tree.display_graphviz());
}

pub async fn display_prover_hint_tree(
    ctx: &SessionContext,
    proof_tree: ProverProofTree<B>,
) {
    init_tracing_for_tests();

    let hint_tree = ProverHintTree::from_proof_tree(ctx, proof_tree)
        .await
        .unwrap();
    hint_tree.arena().keys().for_each(|v| println!("{}", v));
    println!("--------------------------------");
    println!("{}", hint_tree.display_graphviz());
}

pub async fn display_prover_arithmetized_tree(
    ctx: &SessionContext,
    proof_tree: ProverProofTree<B>,
) {
    let hint_tree = ProverHintTree::from_proof_tree(ctx, proof_tree)
        .await
        .unwrap();
    let arith_tree = ProverArithmetizedTree::from_hint_tree(hint_tree).unwrap();
    arith_tree
        .arithmetized_tables()
        .keys()
        .for_each(|v| println!("{}", v));
    println!("--------------------------------");
    println!("{}", arith_tree.display_graphviz());
}

pub async fn display_prover_tracked_tree(
    ctx: &SessionContext,
    proof_tree: ProverProofTree<B>,
) {
    let hint_tree = ProverHintTree::from_proof_tree(ctx, proof_tree)
        .await
        .unwrap();
    let arith_tree = ProverArithmetizedTree::<B>::from_hint_tree(hint_tree).unwrap();
    let (mut prover, _verifier): (Prover<B>, _) = test_prelude().unwrap();
    let tracked_tree = ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover).unwrap();
    tracked_tree.arena().keys().for_each(|v| println!("{}", v));
    println!("--------------------------------");
    println!("{}", tracked_tree.display_graphviz());
}

pub async fn display_prover_piop_tree(
    ctx: &SessionContext,
    proof_tree: ProverProofTree<B>,
) {
    init_tracing_for_tests();
    let hint_tree = ProverHintTree::from_proof_tree(ctx, proof_tree)
        .await
        .unwrap();
    let arith_tree = ProverArithmetizedTree::<B>::from_hint_tree(hint_tree).unwrap();
    let (mut prover, _verifier): (Prover<B>, _) = test_prelude().unwrap();
    let tracked_tree = ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover).unwrap();
    let piop_plan = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);
    piop_plan.arena().keys().for_each(|v| println!("{}", v));
    println!("--------------------------------");
    println!("{}", piop_plan.display_graphviz());
}
