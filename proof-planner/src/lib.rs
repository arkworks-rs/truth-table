use arithmetic::ctx::SharedCtx;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{
    execution::{session_state::SessionStateBuilder, SessionState},
    optimizer::Analyzer,
    prelude::SessionContext,
};
use tracing::instrument;
use truthtable_core::{
    prover::trees::proof_tree::ProverProofTree, verifier::trees::proof_tree::VerifierProofTree,
};

use crate::{
    logical_plan_analyzer::{analyze_logical_plan, logical_plan_analyzer_rules},
    logical_plan_optimizer::optimize_logical_plan,
    proof_plan_optimizer::{
        build_prover_proof_tree, build_verifier_proof_tree, default_shared_ctx,
    },
};

pub mod logical_plan_analyzer;
pub mod logical_plan_optimizer;
pub mod proof_plan_optimizer;

/// Create a new `SessionContext` configured with the custom logical-plan
/// analyzer.
pub fn new_session_context_with_custom_analyzer() -> SessionContext {
    let base_ctx = SessionContext::new();
    let base_state = base_ctx.state();
    let mut builder = SessionStateBuilder::new_from_existing(base_state.clone());

    let mut analyzer = Analyzer::with_rules(logical_plan_analyzer_rules());
    analyzer.function_rewrites = base_state.analyzer().function_rewrites.clone();
    builder.analyzer().replace(analyzer);

    let state = builder.build();
    SessionContext::new_with_state(state)
}

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
    println!("{}", unoptimized_logical_plan.display_graphviz());
    let analyzed_logical_plan = analyze_logical_plan(
        unoptimized_logical_plan.clone(),
        logical_plan_analyzer_rules(),
    );

    println!("{}", analyzed_logical_plan.display_graphviz());

    let optimized_logical_plan = optimize_logical_plan(analyzed_logical_plan.clone());
    println!("{}", optimized_logical_plan.display_graphviz());
    let shared_ctx = default_shared_ctx::<F, MvPCS, UvPCS>();
    build_prover_proof_tree(
        df_session_ctx,
        unoptimized_logical_plan,
        optimized_logical_plan,
        shared_ctx,
    )
}

#[instrument(level = "debug", skip_all)]
pub async fn create_prover_proof_tree_with_ctx<F, MvPCS, UvPCS>(
    df_session_ctx: &SessionContext,
    query: &str,
    shared_ctx: SharedCtx<F, MvPCS, UvPCS>,
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
        shared_ctx,
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
    let shared_ctx = default_shared_ctx::<F, MvPCS, UvPCS>();
    build_verifier_proof_tree(
        df_session_ctx,
        unoptimized_logical_plan,
        optimized_logical_plan,
        shared_ctx,
    )
}

pub async fn create_verifier_proof_tree_with_ctx<F, MvPCS, UvPCS>(
    df_session_ctx: &SessionContext,
    query: &str,
    shared_ctx: SharedCtx<F, MvPCS, UvPCS>,
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
        shared_ctx,
    )
}

// let verifier_ctx = SharedCtx::new(table_oracle_map);

// verifier.set_proof(proof);
// let verifier_proof_tree =
//     VerifierProofTree::from_lp(&ctx, verifier_ctx.clone(), &logical_plan,
// &NodeId::None);
