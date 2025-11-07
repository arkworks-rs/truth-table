use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::{Expr, ExprFunctionExt, LogicalPlan, LogicalPlanBuilder, col, expr::Sort};
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
    let join_lp = node_id.to_lp().unwrap().clone();
    let join = match &join_lp {
        LogicalPlan::Join(join) => join,
        _ => panic!("Expected Join logical plan"),
    };
    let num_key_cols = join.on.len();
    let left_lp = join.left.clone();
    let right_lp = join.right.clone();
    let all_lp = build_concatenated_lp(num_key_cols, &left_lp, &right_lp);
    let mut plans = IndexMap::new();

    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(
            OUTPUT_PLAN_KEY.to_owned(),
            node_id.to_lp().unwrap().clone(),
        ),
    );
    plans.insert(
        JOIN_LEFT_KEY_SUPP.to_string(),
        build_supp_generation_plans::<F, MvPCS, UvPCS>(JOIN_LEFT_KEY_SUPP, &left_lp, num_key_cols),
    );
    plans.insert(
        JOIN_RIGHT_KEY_SUPP.to_string(),
        build_supp_generation_plans::<F, MvPCS, UvPCS>(
            JOIN_RIGHT_KEY_SUPP,
            &right_lp,
            num_key_cols,
        ),
    );

    plans.insert(
        JOIN_OUTPUT_KEY_SUPP.to_string(),
        build_supp_generation_plans::<F, MvPCS, UvPCS>(
            JOIN_OUTPUT_KEY_SUPP,
            &join_lp,
            num_key_cols,
        ),
    );
    plans.insert(
        JOIN_ALL_KEY_SUPP.to_string(),
        build_supp_generation_plans::<F, MvPCS, UvPCS>(JOIN_ALL_KEY_SUPP, &all_lp, num_key_cols),
    );
    plans.insert(
        JOIN_LEFT_KEY_SOURCE.to_string(),
        join_key_source(&join_lp, num_key_cols, true),
    );

    plans.insert(
        JOIN_RIGHT_KEY_SOURCE.to_string(),
        join_key_source(&join_lp, num_key_cols, false),
    );

    plans
}

pub(crate) fn build_supp_generation_plans<F, MvPCS, UvPCS>(
    name: &str,
    plan: &LogicalPlan,
    num_key_cols: usize,
) -> HintGenerationPlan
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    assert!(
        num_key_cols > 0,
        "support generation requires at least one key column"
    );
    let schema = plan.schema();
    assert!(
        schema.fields().len() >= num_key_cols,
        "requested key columns exceed available columns in plan"
    );

    let key_exprs: Vec<Expr> = schema
        .fields()
        .iter()
        .take(num_key_cols)
        .map(|field| col(field.name()))
        .collect();

    let distinct_plan = LogicalPlanBuilder::from(plan.clone())
        .project(key_exprs.clone())
        .expect("failed to build projection for support generation")
        .aggregate(key_exprs, Vec::<Expr>::new())
        .expect("failed to build distinct aggregate for support generation")
        .build()
        .expect("failed to finalize support generation plan");

    HintGenerationPlan::new_materialized(name.to_string(), distinct_plan)
}

fn build_concatenated_lp(
    num_key_cols: usize,
    lp_left: &LogicalPlan,
    lp_right: &LogicalPlan,
) -> LogicalPlan {
    assert!(num_key_cols > 0, "number of key columns must be > 0");
    let left_schema = lp_left.schema();
    let right_schema = lp_right.schema();
    assert!(
        left_schema.fields().len() >= num_key_cols,
        "left plan does not have enough columns"
    );
    assert!(
        right_schema.fields().len() >= num_key_cols,
        "right plan does not have enough columns"
    );

    for idx in 0..num_key_cols {
        let left_field = left_schema.field(idx);
        let right_field = right_schema.field(idx);
        assert!(
            left_field == right_field,
            "mismatched schemas for key column {idx}: left={:?}, right={:?}",
            left_field.name(),
            right_field.name()
        );
    }

    let left_exprs: Vec<Expr> = left_schema
        .fields()
        .iter()
        .take(num_key_cols)
        .map(|field| col(field.name()))
        .collect();
    let right_exprs: Vec<Expr> = right_schema
        .fields()
        .iter()
        .take(num_key_cols)
        .map(|field| col(field.name()))
        .collect();

    let left_projected = LogicalPlanBuilder::from(lp_left.clone())
        .project(left_exprs)
        .expect("failed to build left projection for concatenation")
        .build()
        .expect("failed to finalize left projection for concatenation");
    let right_projected = LogicalPlanBuilder::from(lp_right.clone())
        .project(right_exprs)
        .expect("failed to build right projection for concatenation")
        .build()
        .expect("failed to finalize right projection for concatenation");

    LogicalPlanBuilder::from(left_projected)
        .union(right_projected)
        .expect("failed to union key support plans")
        .build()
        .expect("failed to finalize concatenated plan")
}

pub fn join_key_source(
    join_lp: &LogicalPlan,
    num_key_cols: usize,
    use_left: bool,
) -> HintGenerationPlan {
    // Expect a Join
    let j = match join_lp {
        LogicalPlan::Join(j) => j,
        _ => panic!("expected a Join logical plan"),
    };

    // 1) Add ROW_NUMBER() to the selected input
    assert!(num_key_cols > 0, "number of key columns must be > 0");
    let (key_exprs, base_plan, row_id_alias) = if use_left {
        (
            j.on.iter()
                .map(|(left_expr, _)| left_expr.clone())
                .collect::<Vec<_>>(),
            j.left.as_ref().clone(),
            "__left_row_id",
        )
    } else {
        (
            j.on.iter()
                .map(|(_, right_expr)| right_expr.clone())
                .collect::<Vec<_>>(),
            j.right.as_ref().clone(),
            "__right_row_id",
        )
    };

    assert!(
        key_exprs.len() == num_key_cols,
        "number of key columns does not match join condition"
    );

    let sort_exprs: Vec<Sort> = key_exprs
        .into_iter()
        .map(|expr| Sort {
            expr,
            asc: true,
            nulls_first: true,
        })
        .collect();

    let row_number_expr = row_number()
        .order_by(sort_exprs)
        .build()
        .expect("failed to build row_number window expression")
        .alias(row_id_alias);

    let target_with_id = LogicalPlanBuilder::from(base_plan)
        .window(vec![row_number_expr])
        .expect("failed to append row id window")
        .build()
        .expect("failed to build plan with row id");

    let (left_plan, right_plan) = if use_left {
        (target_with_id.clone(), j.right.as_ref().clone())
    } else {
        (j.left.as_ref().clone(), target_with_id.clone())
    };

    // 2) Rebuild the same join but with the augmented left
    let (left_cols, right_cols): (Vec<_>, Vec<_>) =
        j.on.iter()
            .map(|(left_expr, right_expr)| match (left_expr, right_expr) {
                (Expr::Column(left_col), Expr::Column(right_col)) => {
                    (left_col.clone(), right_col.clone())
                },
                _ => panic!("expected column expression in join condition"),
            })
            .unzip();

    let rebuilt_join = LogicalPlanBuilder::from(left_plan)
        .join(
            right_plan,
            j.join_type,
            (left_cols, right_cols),
            j.filter.clone(),
        )
        .expect("failed to rebuild join with row ids")
        .build()
        .expect("failed to build join with row ids");

    // 3) Project only the id column
    let out = LogicalPlanBuilder::from(rebuilt_join)
        .project(vec![col(row_id_alias)])
        .expect("failed to project left row id column")
        .build()
        .expect("failed to build left row id plan");

    let plan_key = if use_left {
        JOIN_LEFT_KEY_SOURCE
    } else {
        JOIN_RIGHT_KEY_SOURCE
    };

    HintGenerationPlan::new_materialized(plan_key.to_string(), out)
}
