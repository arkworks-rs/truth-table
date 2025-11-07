use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::common::Column;
use datafusion_expr::{
    Expr, ExprFunctionExt, LogicalPlan, LogicalPlanBuilder, col, expr::Sort, logical_plan::Join,
};
use datafusion_functions_window::expr_fn::row_number;
use indexmap::IndexMap;

use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, id::NodeId, prover::ProverNode, verifier::VerifierNode,
    },
    prover::trees::proof_tree::ProverProofTree,
    verifier::trees::proof_tree::VerifierProofTree,
};

pub(crate) const JOIN_LEFT_KEY_SUPP: &str = "__join_left_key_supp__";
pub(crate) const JOIN_RIGHT_KEY_SUPP: &str = "__join_right_key_supp__";
pub(crate) const JOIN_OUTPUT_KEY_SUPP: &str = "__join_output_key_supp__";
pub(crate) const JOIN_ALL_KEY_SUPP: &str = "__join_all_key_supp__";
pub(crate) const JOIN_LEFT_KEY_SOURCE: &str = "__join_left_key_source__";
pub(crate) const JOIN_RIGHT_KEY_SOURCE: &str = "__join_right_key_source__";

pub(crate) fn build_join_hint_generation_plans<F, MvPCS, UvPCS>(
    node_id: NodeId,
) -> IndexMap<String, HintGenerationPlan>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let mut plans = IndexMap::new();
    let join_lp = node_id.to_lp().unwrap().clone();
    let join = match &join_lp {
        LogicalPlan::Join(join) => join,
        _ => panic!("Expected Join logical plan"),
    };
    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_owned(), join_lp),
    );
    // plans.insert(
    //     JOIN_LEFT_KEY_SUPP.to_string(),
    //     build_supp_generation_plans::<F, MvPCS, UvPCS>(JOIN_LEFT_KEY_SUPP,
    // &left_lp, num_key_cols), );
    // plans.insert(
    //     JOIN_RIGHT_KEY_SUPP.to_string(),
    //     build_supp_generation_plans::<F, MvPCS, UvPCS>(
    //         JOIN_RIGHT_KEY_SUPP,
    //         &right_lp,
    //         num_key_cols,
    //     ),
    // );

    // plans.insert(
    //     JOIN_OUTPUT_KEY_SUPP.to_string(),
    //     build_supp_generation_plans::<F, MvPCS, UvPCS>(
    //         JOIN_OUTPUT_KEY_SUPP,
    //         &join_lp_key_alias,
    //         num_key_cols,
    //     ),
    // );
    // plans.insert(
    //     JOIN_ALL_KEY_SUPP.to_string(),
    //     build_supp_generation_plans::<F, MvPCS, UvPCS>(JOIN_ALL_KEY_SUPP,
    // &all_lp, num_key_cols), );
    // plans.insert(
    //     JOIN_LEFT_KEY_SOURCE.to_string(),
    //     join_key_source(&join_lp, num_key_cols, true),
    // );

    // plans.insert(
    //     JOIN_RIGHT_KEY_SOURCE.to_string(),
    //     join_key_source(&join_lp, num_key_cols, false),
    // );

    plans
}
