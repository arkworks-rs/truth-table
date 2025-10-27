use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{execution::SessionState, prelude::SessionContext};
use dbsnark_core::{
    prover::trees::proof_tree::ProverProofTree, verifier::trees::proof_tree::VerifierProofTree,
};

use crate::{
    logical_plan_analyzer::{analyze_logical_plan, logical_plan_analyzer_rules},
    logical_plan_optimizer::optimize_logical_plan,
    proof_plan_optimizer::{build_prover_proof_tree, build_verifier_proof_tree},
};

pub mod logical_plan_analyzer;
pub mod logical_plan_optimizer;
pub mod proof_plan_optimizer;

pub async fn create_prover_proof_tree<F, MvPCS, UvPCS>(
    df_session_ctx: &SessionContext,
    query: &str,
) -> ProverProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync,
{
    let df_session_state: SessionState = df_session_ctx.state();
    let unoptimized_logical_plan = df_session_state.create_logical_plan(query).await.unwrap();

    let analyzed_logical_plan = analyze_logical_plan(
        unoptimized_logical_plan.clone(),
        logical_plan_analyzer_rules(),
    );

    let optimized_logical_plan = optimize_logical_plan(analyzed_logical_plan.clone());
    build_prover_proof_tree(
        df_session_ctx,
        unoptimized_logical_plan,
        optimized_logical_plan,
    )
}

pub async fn create_verifier_proof_tree<F, MvPCS, UvPCS>(
    df_session_ctx: &SessionContext,
    query: &str,
) -> VerifierProofTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync,
{
    let df_session_state: SessionState = df_session_ctx.state();
    let unoptimized_logical_plan = df_session_state.create_logical_plan(query).await.unwrap();

    let analyzed_logical_plan = analyze_logical_plan(
        unoptimized_logical_plan.clone(),
        logical_plan_analyzer_rules(),
    );

    let optimized_logical_plan = optimize_logical_plan(analyzed_logical_plan.clone());
    build_verifier_proof_tree(
        df_session_ctx,
        unoptimized_logical_plan,
        optimized_logical_plan,
    )
}

// let verifier_ctx = SharedCtx::new(table_oracle_map);

// verifier.set_proof(proof);
// let verifier_proof_tree =
//     VerifierProofTree::from_lp(&ctx, verifier_ctx.clone(), &logical_plan,
// &NodeId::None);
