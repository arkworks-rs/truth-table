use std::sync::Arc;

use arithmetic::ACTIVATOR_COL_NAME;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::common::Column;
use datafusion_expr::{
    col, expr::Sort, logical_plan::Join, Expr, ExprFunctionExt, LogicalPlan, LogicalPlanBuilder,
};
use datafusion_functions_window::expr_fn::row_number;
use indexmap::IndexMap;

use crate::{
    proof_nodes::{
        id::NodeId, prover::ProverNode, verifier::VerifierNode, HintGenerationPlan, OUTPUT_PLAN_KEY,
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
    let orig_join_lp = node_id.to_lp().unwrap().clone();
    let join = match &orig_join_lp {
        LogicalPlan::Join(join) => join,
        _ => panic!("Expected Join logical plan"),
    };
    let orig_left_lp = join.left.as_ref();
    let orig_right_lp = join.right.as_ref();

    let preprocessed_join_lp = preprocess_plan(&orig_join_lp);
    let preprocessed_left_lp = preprocess_plan(&orig_left_lp);
    let preprocessed_right_lp = preprocess_plan(&orig_right_lp);

    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(
            OUTPUT_PLAN_KEY.to_owned(),
            preprocessed_join_lp.clone(),
        ),
    );

    let base_output_support_plan = compute_output_support_plan(join, &preprocessed_join_lp);
    let out_supp_plan = build_out_supp_generation_plan::<F, MvPCS, UvPCS>(
        join,
        &preprocessed_join_lp,
        &base_output_support_plan,
    );
    plans.insert(
        JOIN_OUTPUT_KEY_SUPP.to_string(),
        HintGenerationPlan::new_materialized(
            JOIN_OUTPUT_KEY_SUPP.to_string(),
            out_supp_plan.clone(),
        ),
    );
    plans.insert(
        JOIN_LEFT_KEY_SUPP.to_string(),
        build_left_supp_generation_plan::<F, MvPCS, UvPCS>(
            join,
            &preprocessed_left_lp,
            &out_supp_plan,
        ),
    );
    plans.insert(
        JOIN_RIGHT_KEY_SUPP.to_string(),
        build_right_supp_generation_plan::<F, MvPCS, UvPCS>(
            join,
            &preprocessed_right_lp,
            &out_supp_plan,
        ),
    );
    plans.insert(
        JOIN_ALL_KEY_SUPP.to_string(),
        build_all_supp_generation_plan::<F, MvPCS, UvPCS>(
            join,
            &preprocessed_left_lp,
            &preprocessed_right_lp,
            &out_supp_plan,
        ),
    );

    plans.insert(
        JOIN_LEFT_KEY_SOURCE.to_string(),
        join_left_key_source::<F, MvPCS, UvPCS>(&preprocessed_join_lp, join.clone()),
    );
    plans.insert(
        JOIN_RIGHT_KEY_SOURCE.to_string(),
        join_right_key_source::<F, MvPCS, UvPCS>(&preprocessed_join_lp, join.clone()),
    );
    plans
}

/// Remove the `activator` column from the provided plan (if it exists) by
/// inserting a projection that forwards every other column with its original
/// qualifier. Keeping the qualifiers avoids ambiguous column references later
/// in the hint-generation pipeline.
fn strip_activator(plan: &LogicalPlan) -> LogicalPlan {
    let schema = plan.schema();
    let projection_exprs: Vec<Expr> = schema
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() == ACTIVATOR_COL_NAME {
                None
            } else {
                Some(Expr::Column(Column::new(
                    qualifier.cloned(),
                    field.name().clone(),
                )))
            }
        })
        .collect();

    if projection_exprs.len() == schema.fields().len() {
        // Nothing to strip; reuse the original plan to avoid adding redundant
        // projections.
        return plan.clone();
    }

    LogicalPlanBuilder::from(plan.clone())
        .project(projection_exprs)
        .expect("failed to build activator-free projection")
        .build()
        .expect("failed to strip activator column")
}

/// Keep only rows whose `activator` column evaluates to `true`. If the plan
/// lacks an activator column, the original plan is returned unchanged.
fn filter_active_rows(plan: &LogicalPlan) -> LogicalPlan {
    let schema = plan.schema();
    let activator_entry = schema
        .iter()
        .find(|(_, field)| field.name() == ACTIVATOR_COL_NAME);

    let Some((qualifier, _)) = activator_entry else {
        return plan.clone();
    };

    let activator_expr = Expr::Column(Column::new(
        qualifier.cloned(),
        ACTIVATOR_COL_NAME.to_string(),
    ));

    LogicalPlanBuilder::from(plan.clone())
        .filter(activator_expr)
        .expect("failed to add activator filter")
        .build()
        .expect("failed to keep only active rows")
}

/// Convenience helper that keeps only active rows and then removes the
/// activator column entirely.
fn preprocess_plan(plan: &LogicalPlan) -> LogicalPlan {
    let filtered = filter_active_rows(plan);
    strip_activator(&filtered)
}

fn compute_output_support_plan(join: &Join, join_lp: &LogicalPlan) -> LogicalPlan {
    let sanitized_join = preprocess_plan(join_lp);
    let output_key_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(left_expr, _)| left_expr.clone())
        .collect();

    LogicalPlanBuilder::from(sanitized_join)
        .project(output_key_exprs.clone())
        .expect("failed to project join output keys")
        .aggregate(output_key_exprs, Vec::<Expr>::new())
        .expect("failed to aggregate distinct join output keys")
        .build()
        .expect("failed to compute output key support plan")
}

fn merge_support_plans(
    existing_plan: &LogicalPlan,
    new_plan: LogicalPlan,
    key_count: usize,
) -> LogicalPlan {
    let union_plan = LogicalPlanBuilder::from(existing_plan.clone())
        .union(new_plan)
        .expect("failed to union support plan with output support")
        .build()
        .expect("failed to build union plan for support merge");

    let key_columns: Vec<Expr> = union_plan
        .schema()
        .fields()
        .iter()
        .take(key_count)
        .map(|field| col(field.name()))
        .collect();

    let merged_distinct = LogicalPlanBuilder::from(union_plan.clone())
        .aggregate(key_columns.clone(), Vec::<Expr>::new())
        .expect("failed to aggregate merged support plan")
        .build()
        .expect("failed to finalize merged support plan");

    let sort_exprs: Vec<Sort> = key_columns
        .into_iter()
        .map(|expr| Sort {
            expr,
            asc: true,
            nulls_first: true,
        })
        .collect();

    LogicalPlanBuilder::from(merged_distinct)
        .sort(sort_exprs)
        .expect("failed to sort merged support plan")
        .build()
        .expect("failed to finalize sorted support plan")
}

/// Build the left-key support plan by selecting the join's left key columns,
/// projecting them, and aggregating to retain only distinct tuples.
pub(crate) fn build_left_supp_generation_plan<F, MvPCS, UvPCS>(
    join: &Join,
    left_lp: &LogicalPlan,
    output_key_supp_plan: &LogicalPlan,
) -> HintGenerationPlan
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let left_key_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(left_expr, _)| left_expr.clone())
        .collect();
    assert!(
        !left_key_exprs.is_empty(),
        "join must contain at least one key column"
    );

    let sanitized_left = preprocess_plan(left_lp);
    let distinct_plan = LogicalPlanBuilder::from(sanitized_left)
        .project(left_key_exprs.clone())
        .expect("failed to project left join keys")
        .aggregate(left_key_exprs.clone(), Vec::<Expr>::new())
        .expect("failed to aggregate distinct left join keys")
        .build()
        .expect("failed to finalize left key support plan");

    let merged_plan =
        merge_support_plans(output_key_supp_plan, distinct_plan, left_key_exprs.len());

    HintGenerationPlan::new_materialized(JOIN_LEFT_KEY_SUPP.to_string(), merged_plan)
}

/// Build the right-key support plan by selecting the join's right key columns,
/// projecting them, and aggregating to retain only distinct tuples.
pub(crate) fn build_right_supp_generation_plan<F, MvPCS, UvPCS>(
    join: &Join,
    right_lp: &LogicalPlan,
    output_key_supp_plan: &LogicalPlan,
) -> HintGenerationPlan
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let right_key_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(_, right_expr)| right_expr.clone())
        .collect();
    assert!(
        !right_key_exprs.is_empty(),
        "join must contain at least one key column"
    );

    let sanitized_right = preprocess_plan(right_lp);
    let distinct_plan = LogicalPlanBuilder::from(sanitized_right)
        .project(right_key_exprs.clone())
        .expect("failed to project right join keys")
        .aggregate(right_key_exprs.clone(), Vec::<Expr>::new())
        .expect("failed to aggregate distinct right join keys")
        .build()
        .expect("failed to finalize right key support plan");

    let merged_plan =
        merge_support_plans(output_key_supp_plan, distinct_plan, right_key_exprs.len());

    HintGenerationPlan::new_materialized(JOIN_RIGHT_KEY_SUPP.to_string(), merged_plan)
}

/// Build the output-key support plan from the join result itself.
pub(crate) fn build_out_supp_generation_plan<F, MvPCS, UvPCS>(
    join: &Join,
    join_lp: &LogicalPlan,
    output_key_supp_plan: &LogicalPlan,
) -> LogicalPlan
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let output_key_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(left_expr, _)| left_expr.clone())
        .collect();
    assert!(
        !output_key_exprs.is_empty(),
        "join must contain at least one key column"
    );

    let sanitized_join = preprocess_plan(join_lp);
    let distinct_plan = LogicalPlanBuilder::from(sanitized_join)
        .project(output_key_exprs.clone())
        .expect("failed to project join output keys")
        .aggregate(output_key_exprs.clone(), Vec::<Expr>::new())
        .expect("failed to aggregate distinct join output keys")
        .build()
        .expect("failed to finalize join output key support plan");

    merge_support_plans(output_key_supp_plan, distinct_plan, output_key_exprs.len())
}

/// Build the all-key support plan by unioning the left/right key supports and
/// deduplicating the combined relation.
pub(crate) fn build_all_supp_generation_plan<F, MvPCS, UvPCS>(
    join: &Join,
    left_lp: &LogicalPlan,
    right_lp: &LogicalPlan,
    output_key_supp_plan: &LogicalPlan,
) -> HintGenerationPlan
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let left_support_plan =
        build_left_supp_generation_plan::<F, MvPCS, UvPCS>(join, left_lp, output_key_supp_plan)
            .plan()
            .clone();
    let right_support_plan =
        build_right_supp_generation_plan::<F, MvPCS, UvPCS>(join, right_lp, output_key_supp_plan)
            .plan()
            .clone();

    let union_plan = LogicalPlanBuilder::from(left_support_plan)
        .union(right_support_plan)
        .expect("failed to union left/right key supports")
        .build()
        .expect("failed to build union of key supports");

    let key_exprs: Vec<Expr> = union_plan
        .schema()
        .fields()
        .iter()
        .map(|field| col(field.name()))
        .collect();

    let distinct_plan = LogicalPlanBuilder::from(union_plan)
        .aggregate(key_exprs, Vec::<Expr>::new())
        .expect("failed to aggregate distinct union of key supports")
        .build()
        .expect("failed to finalize all key support plan");

    HintGenerationPlan::new_materialized(JOIN_ALL_KEY_SUPP.to_string(), distinct_plan)
}

pub(crate) fn join_left_key_source<F, MvPCS, UvPCS>(
    _join_lp: &LogicalPlan,
    join: Join,
) -> HintGenerationPlan
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let left_key_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(left_expr, _)| left_expr.clone())
        .collect();
    assert!(
        !left_key_exprs.is_empty(),
        "join must contain at least one key column"
    );

    let sort_exprs: Vec<Sort> = left_key_exprs
        .iter()
        .cloned()
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
        .alias("__left_row_id");

    let left_with_id = LogicalPlanBuilder::from(preprocess_plan(join.left.as_ref()))
        .window(vec![row_number_expr])
        .expect("failed to append left row ids")
        .build()
        .expect("failed to build left plan with row ids");

    let (left_cols, right_cols): (Vec<_>, Vec<_>) = join
        .on
        .iter()
        .map(|(left_expr, right_expr)| match (left_expr, right_expr) {
            (Expr::Column(left_col), Expr::Column(right_col)) => {
                (left_col.clone(), right_col.clone())
            },
            _ => panic!("expected column expressions in join condition"),
        })
        .unzip();

    let rebuilt_join = LogicalPlanBuilder::from(left_with_id)
        .join(
            preprocess_plan(join.right.as_ref()),
            join.join_type,
            (left_cols, right_cols),
            join.filter.clone(),
        )
        .expect("failed to rebuild join with left row ids")
        .build()
        .expect("failed to build join with left row ids");

    let projection = LogicalPlanBuilder::from(rebuilt_join)
        .project(vec![col("__left_row_id")])
        .expect("failed to project left row id")
        .build()
        .expect("failed to finalize left row id projection");

    HintGenerationPlan::new_materialized(JOIN_LEFT_KEY_SOURCE.to_string(), projection)
}

pub(crate) fn join_right_key_source<F, MvPCS, UvPCS>(
    _join_lp: &LogicalPlan,
    join: Join,
) -> HintGenerationPlan
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let right_key_exprs: Vec<Expr> = join
        .on
        .iter()
        .map(|(_, right_expr)| right_expr.clone())
        .collect();
    assert!(
        !right_key_exprs.is_empty(),
        "join must contain at least one key column"
    );

    let sort_exprs: Vec<Sort> = right_key_exprs
        .iter()
        .cloned()
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
        .alias("__right_row_id");

    let right_with_id = LogicalPlanBuilder::from(preprocess_plan(join.right.as_ref()))
        .window(vec![row_number_expr])
        .expect("failed to append right row ids")
        .build()
        .expect("failed to build right plan with row ids");

    let (left_cols, right_cols): (Vec<_>, Vec<_>) = join
        .on
        .iter()
        .map(|(left_expr, right_expr)| match (left_expr, right_expr) {
            (Expr::Column(left_col), Expr::Column(right_col)) => {
                (left_col.clone(), right_col.clone())
            },
            _ => panic!("expected column expressions in join condition"),
        })
        .unzip();

    let rebuilt_join = LogicalPlanBuilder::from(preprocess_plan(join.left.as_ref()))
        .join(
            right_with_id,
            join.join_type,
            (left_cols, right_cols),
            join.filter.clone(),
        )
        .expect("failed to rebuild join with right row ids")
        .build()
        .expect("failed to build join with right row ids");

    let projection = LogicalPlanBuilder::from(rebuilt_join)
        .project(vec![col("__right_row_id")])
        .expect("failed to project right row id")
        .build()
        .expect("failed to finalize right row id projection");

    HintGenerationPlan::new_materialized(JOIN_RIGHT_KEY_SOURCE.to_string(), projection)
}
