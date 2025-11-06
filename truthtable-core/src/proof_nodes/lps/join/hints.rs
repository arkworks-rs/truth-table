use super::OUTPUT_PLAN_KEY;
use crate::proof_nodes::HintGenerationPlan;
use datafusion::{
    common::{DataFusionError, Result as DFResult},
    logical_expr::Join,
    prelude::Column,
};
use datafusion_expr::{
    Expr, LogicalPlan, col, expr::WildcardOptions, lit, logical_plan::builder::LogicalPlanBuilder,
};
use datafusion_functions_aggregate::expr_fn::count;
use datafusion_functions_window::expr_fn::row_number;
use indexmap::IndexMap;

pub const SUPPORT_ROLE_COL: &str = "__truthtable_join_support_role";
pub const SUPPORT_VALUE_COL: &str = "__truthtable_join_support_value";
pub const SUPPORT_COUNT_COL: &str = "__truthtable_join_support_count";
pub const SOURCE_ROLE_COL: &str = "__truthtable_join_source_role";
pub const SOURCE_VALUE_COL: &str = "__truthtable_join_source_value";
pub const SOURCE_INDEX_COL: &str = "__truthtable_join_source_index";
pub const OUTPUT_INDEX_COL: &str = "__truthtable_join_output_index";
pub const OUTPUT_KEY_SUPPORT_COL: &str = "__truthtable_join_output_key_support";

pub const LEFT_SUPPORT_HINT_PREFIX: &str = "left_support_hints";
pub const RIGHT_SUPPORT_HINT_PREFIX: &str = "right_support_hints";
pub const OUTPUT_SUPPORT_HINT_PREFIX: &str = "output_support_hints";
pub const COMBINED_SUPPORT_HINT_PREFIX: &str = "support_hints";
pub const LEFT_SOURCE_HINT_PREFIX: &str = "left_source_hints";
pub const RIGHT_SOURCE_HINT_PREFIX: &str = "right_source_hints";
pub const COMBINED_SOURCE_HINT_PREFIX: &str = "source_hints";
pub const OUTPUT_KEY_SUPPORT_HINT: &str = "output_key_support";

const SUPPORT_ROLE_LEFT: &str = "left_support";
const SUPPORT_ROLE_RIGHT: &str = "right_support";
const SUPPORT_ROLE_OUTPUT: &str = "output_support";
const SOURCE_ROLE_LEFT: &str = "left_source";
const SOURCE_ROLE_RIGHT: &str = "right_source";

fn hint_label(prefix: &str, idx: usize) -> String {
    format!("{prefix}[{idx}]")
}

fn materialized_hint(name: String, plan: LogicalPlan) -> HintGenerationPlan {
    HintGenerationPlan::new_materialized(name, plan)
}

fn value_alias(base: &str, idx: usize) -> String {
    format!("__truthtable_join_on{idx}_{base}")
}

/// Build every hinted plan needed by the join prover (output, support, source
/// indices, key support).
pub fn build_join_hint_generation_plans(plan: LogicalPlan) -> IndexMap<String, HintGenerationPlan> {
    let mut plans = IndexMap::new();
    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        materialized_hint(OUTPUT_PLAN_KEY.to_string(), plan.clone()),
    );
    plans.extend(build_support_hint_plans(&plan));
    plans.extend(build_source_hint_plans(&plan));
    plans.insert(
        OUTPUT_KEY_SUPPORT_HINT.to_string(),
        materialized_hint(
            OUTPUT_KEY_SUPPORT_HINT.to_string(),
            build_output_key_support_plan(&plan),
        ),
    );
    plans
}

/// Verifier side consumes the exact same hint plans.
pub fn build_verifier_join_hint_generation_plans(
    plan: LogicalPlan,
) -> IndexMap<String, HintGenerationPlan> {
    build_join_hint_generation_plans(plan)
}

/// Build per-equality support plans (left/right/input combined) that track key
/// multiplicities.
fn build_support_hint_plans(plan: &LogicalPlan) -> IndexMap<String, HintGenerationPlan> {
    let join = match plan {
        LogicalPlan::Join(join) => join,
        other => panic!("expected join logical plan, found {:?}", other),
    };

    let mut support_plans = IndexMap::new();
    for (idx, (left_expr, right_expr)) in join.on.iter().enumerate() {
        let (left_plan, right_plan, output_plan, combined_plan) =
            build_support_hint_plans_for_pair(plan, join, idx, left_expr, right_expr)
                .unwrap_or_else(|err| {
                    panic!(
                        "failed to build support hint plan for join equality {}: {}",
                        idx, err
                    )
                });

        let left_hint_name = hint_label(LEFT_SUPPORT_HINT_PREFIX, idx);
        support_plans.insert(
            left_hint_name.clone(),
            materialized_hint(left_hint_name, left_plan),
        );

        let right_hint_name = hint_label(RIGHT_SUPPORT_HINT_PREFIX, idx);
        support_plans.insert(
            right_hint_name.clone(),
            materialized_hint(right_hint_name, right_plan),
        );

        let output_hint_name = hint_label(OUTPUT_SUPPORT_HINT_PREFIX, idx);
        support_plans.insert(
            output_hint_name.clone(),
            materialized_hint(output_hint_name, output_plan),
        );

        let combined_hint_name = hint_label(COMBINED_SUPPORT_HINT_PREFIX, idx);
        support_plans.insert(
            combined_hint_name.clone(),
            materialized_hint(combined_hint_name, combined_plan),
        );
    }

    support_plans
}

/// Build the three support plans for a single equality predicate along with
/// their union.
fn build_support_hint_plans_for_pair(
    plan: &LogicalPlan,
    join: &Join,
    idx: usize,
    left_expr: &Expr,
    right_expr: &Expr,
) -> DFResult<(LogicalPlan, LogicalPlan, LogicalPlan, LogicalPlan)> {
    let left_alias = value_alias("left_value", idx);
    let left_counts = build_value_count_plan(&(*join.left).clone(), left_expr, &left_alias)?;
    let left_support_plan = LogicalPlanBuilder::from(left_counts)
        .project(vec![
            lit(SUPPORT_ROLE_LEFT).alias(SUPPORT_ROLE_COL),
            col(&left_alias).alias(SUPPORT_VALUE_COL),
            col(SUPPORT_COUNT_COL).alias(SUPPORT_COUNT_COL),
        ])?
        .build()?;

    let right_alias = value_alias("right_value", idx);
    let right_counts = build_value_count_plan(&(*join.right).clone(), right_expr, &right_alias)?;
    let right_support_plan = LogicalPlanBuilder::from(right_counts)
        .project(vec![
            lit(SUPPORT_ROLE_RIGHT).alias(SUPPORT_ROLE_COL),
            col(&right_alias).alias(SUPPORT_VALUE_COL),
            col(SUPPORT_COUNT_COL).alias(SUPPORT_COUNT_COL),
        ])?
        .build()?;

    let combined_alias = value_alias("output_value", idx);
    let output_counts = build_output_key_count_plan(join, left_expr, &combined_alias)?;
    let output_support_plan = LogicalPlanBuilder::from(output_counts)
        .project(vec![
            lit(SUPPORT_ROLE_OUTPUT).alias(SUPPORT_ROLE_COL),
            col(&combined_alias).alias(SUPPORT_VALUE_COL),
            col(SUPPORT_COUNT_COL).alias(SUPPORT_COUNT_COL),
        ])?
        .build()?;

    let combined_plan = LogicalPlanBuilder::from(left_support_plan.clone())
        .union(right_support_plan.clone())?
        .union(output_support_plan.clone())?
        .build()?;

    Ok((
        left_support_plan,
        right_support_plan,
        output_support_plan,
        combined_plan,
    ))
}

/// Build per-equality source plans connecting join outputs back to their
/// originating rows.
fn build_source_hint_plans(plan: &LogicalPlan) -> IndexMap<String, HintGenerationPlan> {
    let join = match plan {
        LogicalPlan::Join(join) => join,
        other => panic!("expected join logical plan, found {:?}", other),
    };

    let mut source_plans = IndexMap::new();
    for (idx, (left_expr, right_expr)) in join.on.iter().enumerate() {
        let (left_plan, right_plan, combined_plan) = build_source_hint_plans_for_pair(
            join, idx, left_expr, right_expr,
        )
        .unwrap_or_else(|err| {
            panic!(
                "failed to build source hint plan for join equality {}: {}",
                idx, err
            )
        });

        let left_hint_name = hint_label(LEFT_SOURCE_HINT_PREFIX, idx);
        source_plans.insert(
            left_hint_name.clone(),
            materialized_hint(left_hint_name, left_plan),
        );

        let right_hint_name = hint_label(RIGHT_SOURCE_HINT_PREFIX, idx);
        source_plans.insert(
            right_hint_name.clone(),
            materialized_hint(right_hint_name, right_plan),
        );

        let combined_hint_name = hint_label(COMBINED_SOURCE_HINT_PREFIX, idx);
        source_plans.insert(
            combined_hint_name.clone(),
            materialized_hint(combined_hint_name, combined_plan),
        );
    }

    source_plans
}

/// Build the source index plans for one predicate: left-only, right-only, and
/// the union.
fn build_source_hint_plans_for_pair(
    join: &Join,
    idx: usize,
    left_expr: &Expr,
    right_expr: &Expr,
) -> DFResult<(LogicalPlan, LogicalPlan, LogicalPlan)> {
    let left_value_alias = value_alias("left_value", idx);
    let right_value_alias = value_alias("right_value", idx);
    let left_index_alias = value_alias("left_index", idx);
    let right_index_alias = value_alias("right_index", idx);

    let left_with_idx = annotate_input_with_index(
        &(*join.left).clone(),
        left_expr,
        &left_value_alias,
        &left_index_alias,
    )?;
    let right_with_idx = annotate_input_with_index(
        &(*join.right).clone(),
        right_expr,
        &right_value_alias,
        &right_index_alias,
    )?;

    let (left_join_cols, right_join_cols): (Vec<_>, Vec<_>) = join
        .on
        .iter()
        .map(|(l, r)| Ok((expr_to_column(l)?, expr_to_column(r)?)))
        .collect::<DFResult<Vec<_>>>()?
        .into_iter()
        .unzip();

    let join_plan = LogicalPlanBuilder::from(left_with_idx)
        .join_detailed(
            right_with_idx,
            join.join_type,
            (left_join_cols, right_join_cols),
            join.filter.clone(),
            join.null_equals_null,
        )?
        .build()?;

    let output_row_number_alias = value_alias("output_row_number", idx);
    let join_with_output_idx = LogicalPlanBuilder::from(join_plan)
        .window(vec![row_number().alias(output_row_number_alias.clone())])?
        .build()?;

    let left_projection = LogicalPlanBuilder::from(join_with_output_idx.clone())
        .project(vec![
            (col(&output_row_number_alias) - lit(1_i64)).alias(OUTPUT_INDEX_COL),
            lit(SOURCE_ROLE_LEFT).alias(SOURCE_ROLE_COL),
            col(&left_index_alias).alias(SOURCE_INDEX_COL),
            col(&left_value_alias).alias(SOURCE_VALUE_COL),
        ])?
        .build()?;

    let right_projection = LogicalPlanBuilder::from(join_with_output_idx)
        .project(vec![
            (col(&output_row_number_alias) - lit(1_i64)).alias(OUTPUT_INDEX_COL),
            lit(SOURCE_ROLE_RIGHT).alias(SOURCE_ROLE_COL),
            col(&right_index_alias).alias(SOURCE_INDEX_COL),
            col(&right_value_alias).alias(SOURCE_VALUE_COL),
        ])?
        .build()?;

    let combined_plan = LogicalPlanBuilder::from(left_projection.clone())
        .union(right_projection.clone())?
        .build()?;

    Ok((left_projection, right_projection, combined_plan))
}

/// Count occurrences of `expr` within `input`, returning `(value, count)`
/// pairs.
fn build_value_count_plan(
    input: &LogicalPlan,
    expr: &Expr,
    value_alias: &str,
) -> DFResult<LogicalPlan> {
    LogicalPlanBuilder::from(input.clone())
        .project(vec![expr.clone().alias(value_alias.to_string())])?
        .aggregate(
            vec![col(value_alias)],
            vec![count(lit(1_i64)).alias(SUPPORT_COUNT_COL)],
        )?
        .build()
}

/// Annotate an input plan with the zero-based row index aligned to the
/// row-number window.
fn annotate_input_with_index(
    input: &LogicalPlan,
    value_expr: &Expr,
    value_alias: &str,
    index_alias: &str,
) -> DFResult<LogicalPlan> {
    let row_number_alias = format!("{index_alias}__row_number");
    LogicalPlanBuilder::from(input.clone())
        .window(vec![row_number().alias(row_number_alias.clone())])?
        .project({
            let mut exprs = vec![Expr::Wildcard {
                qualifier: None,
                options: Box::new(WildcardOptions::default()),
            }];
            exprs.push(value_expr.clone().alias(value_alias.to_string()));
            exprs.push((col(&row_number_alias) - lit(1_i64)).alias(index_alias.to_string()));
            exprs
        })?
        .build()
}

fn expr_to_column(expr: &Expr) -> DFResult<Column> {
    if let Expr::Column(col) = expr {
        Ok(col.clone())
    } else {
        Err(DataFusionError::Plan(format!(
            "expected column expression in join equality, found {}",
            expr
        )))
    }
}

/// Track the distinct values that participate in the output key support
/// relation.
fn build_output_key_support_plan(plan: &LogicalPlan) -> LogicalPlan {
    let join = match plan {
        LogicalPlan::Join(join) => join,
        other => panic!("expected join logical plan, found {:?}", other),
    };

    let (left_expr, _) = join
        .on
        .first()
        .expect("join node missing equality conditions for output key support");

    build_output_key_support_plan_for_expr(join, left_expr).unwrap_or_else(|err| {
        panic!(
            "failed to build output key support hint plan for join: {}",
            err
        )
    })
}

fn build_output_key_support_plan_for_expr(join: &Join, expr: &Expr) -> DFResult<LogicalPlan> {
    let join_plan = LogicalPlan::Join(join.clone());
    LogicalPlanBuilder::from(join_plan)
        .project(vec![expr.clone().alias(OUTPUT_KEY_SUPPORT_COL.to_string())])?
        .distinct()?
        .build()
}

fn build_output_key_count_plan(join: &Join, expr: &Expr, alias: &str) -> DFResult<LogicalPlan> {
    let join_plan = LogicalPlan::Join(join.clone());
    LogicalPlanBuilder::from(join_plan)
        .project(vec![expr.clone().alias(alias.to_string())])?
        .aggregate(
            vec![col(alias)],
            vec![count(lit(1_i64)).alias(SUPPORT_COUNT_COL)],
        )?
        .build()
}
