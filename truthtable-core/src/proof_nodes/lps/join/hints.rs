use std::sync::Arc;

use arithmetic::ACTIVATOR_COL_NAME;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::{common::Column, scalar::ScalarValue};
use datafusion_expr::{
    Expr, ExprFunctionExt, LogicalPlan, LogicalPlanBuilder, WindowFrame, build_join_schema, col,
    expr::Sort, logical_plan::Join,
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
const SUPPORT_SOURCE_COL: &str = "__join_support_source__";

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

    let preprocessed_left_lp = preprocess_plan(&orig_left_lp);
    let preprocessed_right_lp = preprocess_plan(&orig_right_lp);
    let output_plan = build_output_plan(join, &preprocessed_left_lp, &preprocessed_right_lp);
    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_owned(), output_plan.clone()),
    );

    let base_output_support_plan = compute_output_support_plan(join, &output_plan);
    let out_supp_plan = build_out_supp_generation_plan::<F, MvPCS, UvPCS>(
        join,
        &output_plan,
        &base_output_support_plan,
    );
    plans.insert(
        JOIN_OUTPUT_KEY_SUPP.to_string(),
        HintGenerationPlan::new_materialized(
            JOIN_OUTPUT_KEY_SUPP.to_string(),
            out_supp_plan.clone(),
        ),
    );
    let (left_supp_plan, left_diff_plan) = build_left_supp_generation_plan::<F, MvPCS, UvPCS>(
        join,
        &preprocessed_left_lp,
        &out_supp_plan,
    );
    plans.insert(JOIN_LEFT_KEY_SUPP.to_string(), left_supp_plan);

    let (right_supp_plan, right_diff_plan) = build_right_supp_generation_plan::<F, MvPCS, UvPCS>(
        join,
        &preprocessed_right_lp,
        &out_supp_plan,
    );
    plans.insert(JOIN_RIGHT_KEY_SUPP.to_string(), right_supp_plan);
    plans.insert(
        JOIN_ALL_KEY_SUPP.to_string(),
        build_all_supp_generation_plan::<F, MvPCS, UvPCS>(
            join,
            &out_supp_plan,
            left_diff_plan,
            right_diff_plan,
        ),
    );

    plans.insert(
        JOIN_LEFT_KEY_SOURCE.to_string(),
        join_left_key_source::<F, MvPCS, UvPCS>(&output_plan, join.clone()),
    );
    plans.insert(
        JOIN_RIGHT_KEY_SOURCE.to_string(),
        join_right_key_source::<F, MvPCS, UvPCS>(&output_plan, join.clone()),
    );
    plans
}

fn build_output_plan(
    join: &Join,
    preprocessed_left_lp: &LogicalPlan,
    preprocessed_right_lp: &LogicalPlan,
) -> LogicalPlan {
    let left_plan = Arc::new(preprocessed_left_lp.clone());
    let right_plan = Arc::new(preprocessed_right_lp.clone());

    let join_schema = build_join_schema(
        left_plan.schema().as_ref(),
        right_plan.schema().as_ref(),
        &join.join_type,
    )
    .expect("failed to derive schema for sanitized join output");

    LogicalPlan::Join(Join {
        left: left_plan,
        right: right_plan,
        on: join.on.clone(),
        filter: join.filter.clone(),
        join_type: join.join_type,
        join_constraint: join.join_constraint,
        schema: Arc::new(join_schema),
        null_equals_null: join.null_equals_null,
    })
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

    let distinct_plan = LogicalPlanBuilder::from(sanitized_join)
        .project(output_key_exprs.clone())
        .expect("failed to project join output keys")
        .aggregate(output_key_exprs, Vec::<Expr>::new())
        .expect("failed to aggregate distinct join output keys")
        .build()
        .expect("failed to compute output key support plan");

    sort_plan_by_keys(distinct_plan, join.on.len())
}

fn sort_plan_by_keys(plan: LogicalPlan, key_count: usize) -> LogicalPlan {
    if key_count == 0 {
        return plan;
    }

    let sort_exprs: Vec<Sort> = plan
        .schema()
        .fields()
        .iter()
        .take(key_count)
        .map(|field| Sort {
            expr: col(field.name()),
            asc: true,
            nulls_first: true,
        })
        .collect();

    LogicalPlanBuilder::from(plan)
        .sort(sort_exprs)
        .expect("failed to sort support plan")
        .build()
        .expect("failed to finalize sorted support plan")
}

fn merge_support_plans(
    existing_plan: &LogicalPlan,
    new_plan: LogicalPlan,
    key_count: usize,
) -> (LogicalPlan, LogicalPlan) {
    let diff_plan = LogicalPlanBuilder::except(new_plan, existing_plan.clone(), false)
        .expect("failed to compute support plan difference");
    let sorted_diff = sort_plan_by_keys(diff_plan, key_count);

    let merged_plan = append_diff_after_output(existing_plan, sorted_diff.clone(), key_count);

    (merged_plan, sorted_diff)
}

fn append_diff_after_output(
    output_plan: &LogicalPlan,
    diff_plan: LogicalPlan,
    key_count: usize,
) -> LogicalPlan {
    if key_count == 0 {
        return output_plan.clone();
    }

    let tagged_output = tag_support_plan(output_plan.clone(), 0);
    let tagged_diff = tag_support_plan(diff_plan, 1);

    let union_plan = LogicalPlanBuilder::from(tagged_output)
        .union(tagged_diff)
        .expect("failed to union support plans with tags")
        .build()
        .expect("failed to build tagged support union");

    let mut sort_exprs = vec![Sort {
        expr: col(SUPPORT_SOURCE_COL),
        asc: true,
        nulls_first: true,
    }];
    sort_exprs.extend(
        union_plan
            .schema()
            .fields()
            .iter()
            .take(key_count)
            .map(|field| Sort {
                expr: col(field.name()),
                asc: true,
                nulls_first: true,
            }),
    );

    let sorted = LogicalPlanBuilder::from(union_plan)
        .sort(sort_exprs)
        .expect("failed to sort tagged support union")
        .build()
        .expect("failed to build sorted tagged support union");

    let projection_exprs: Vec<Expr> = sorted
        .schema()
        .fields()
        .iter()
        .filter(|field| field.name() != SUPPORT_SOURCE_COL)
        .map(|field| col(field.name()))
        .collect();

    LogicalPlanBuilder::from(sorted)
        .project(projection_exprs)
        .expect("failed to drop support source tag")
        .build()
        .expect("failed to finalize aligned support plan")
}

fn tag_support_plan(plan: LogicalPlan, tag: u32) -> LogicalPlan {
    let mut projection_exprs: Vec<Expr> = plan
        .schema()
        .fields()
        .iter()
        .map(|field| col(field.name()))
        .collect();
    projection_exprs.push(Expr::Literal(ScalarValue::UInt32(Some(tag))).alias(SUPPORT_SOURCE_COL));

    LogicalPlanBuilder::from(plan)
        .project(projection_exprs)
        .expect("failed to tag support plan")
        .build()
        .expect("failed to build tagged support plan")
}

/// Build the left-key support plan by selecting the join's left key columns,
/// projecting them, and aggregating to retain only distinct tuples.
pub(crate) fn build_left_supp_generation_plan<F, MvPCS, UvPCS>(
    join: &Join,
    left_lp: &LogicalPlan,
    output_key_supp_plan: &LogicalPlan,
) -> (HintGenerationPlan, LogicalPlan)
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

    let (merged_plan, diff_plan) =
        merge_support_plans(output_key_supp_plan, distinct_plan, left_key_exprs.len());

    (
        HintGenerationPlan::new_materialized(JOIN_LEFT_KEY_SUPP.to_string(), merged_plan),
        diff_plan,
    )
}

/// Build the right-key support plan by selecting the join's right key columns,
/// projecting them, and aggregating to retain only distinct tuples.
pub(crate) fn build_right_supp_generation_plan<F, MvPCS, UvPCS>(
    join: &Join,
    right_lp: &LogicalPlan,
    output_key_supp_plan: &LogicalPlan,
) -> (HintGenerationPlan, LogicalPlan)
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

    let (merged_plan, diff_plan) =
        merge_support_plans(output_key_supp_plan, distinct_plan, right_key_exprs.len());

    (
        HintGenerationPlan::new_materialized(JOIN_RIGHT_KEY_SUPP.to_string(), merged_plan),
        diff_plan,
    )
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

    let (aligned_plan, _) =
        merge_support_plans(output_key_supp_plan, distinct_plan, output_key_exprs.len());

    aligned_plan
}

/// Build the all-key support plan by unioning the left/right key supports and
/// deduplicating the combined relation.
pub(crate) fn build_all_supp_generation_plan<F, MvPCS, UvPCS>(
    join: &Join,
    output_key_supp_plan: &LogicalPlan,
    left_diff_plan: LogicalPlan,
    right_diff_plan: LogicalPlan,
) -> HintGenerationPlan
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    assert!(
        !join.on.is_empty(),
        "join must contain at least one key column"
    );

    let deltas_union = LogicalPlanBuilder::from(left_diff_plan)
        .union(right_diff_plan)
        .expect("failed to union support deltas")
        .build()
        .expect("failed to build union of support deltas");

    let key_exprs: Vec<Expr> = deltas_union
        .schema()
        .fields()
        .iter()
        .take(join.on.len())
        .map(|field| col(field.name()))
        .collect();

    let deduped_deltas = LogicalPlanBuilder::from(deltas_union)
        .aggregate(key_exprs, Vec::<Expr>::new())
        .expect("failed to aggregate support deltas")
        .build()
        .expect("failed to finalize support delta plan");

    let sorted_deltas = sort_plan_by_keys(deduped_deltas, join.on.len());

    let final_plan = append_diff_after_output(output_key_supp_plan, sorted_deltas, join.on.len());

    HintGenerationPlan::new_materialized(JOIN_ALL_KEY_SUPP.to_string(), final_plan)
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

    let row_number_expr = row_number()
        .window_frame(WindowFrame::new(None))
        .build()
        .expect("failed to build row_number window expression")
        .alias("__left_row_id_tmp");

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

    let zero_based_row_id = (col("__left_row_id_tmp")
        - Expr::Literal(ScalarValue::UInt64(Some(1))))
    .alias("__left_row_id");
    let projection = LogicalPlanBuilder::from(rebuilt_join)
        .project(vec![zero_based_row_id])
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

    let row_number_expr = row_number()
        .window_frame(WindowFrame::new(None))
        .build()
        .expect("failed to build row_number window expression")
        .alias("__right_row_id_tmp");

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

    let zero_based_row_id = (col("__right_row_id_tmp")
        - Expr::Literal(ScalarValue::UInt64(Some(1))))
    .alias("__right_row_id");
    let projection = LogicalPlanBuilder::from(rebuilt_join)
        .project(vec![zero_based_row_id])
        .expect("failed to project right row id")
        .build()
        .expect("failed to finalize right row id projection");

    HintGenerationPlan::new_materialized(JOIN_RIGHT_KEY_SOURCE.to_string(), projection)
}
