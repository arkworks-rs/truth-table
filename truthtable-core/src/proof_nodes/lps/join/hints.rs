use super::OUTPUT_PLAN_KEY;
use crate::proof_nodes::HintGenerationPlan;
use datafusion::{
    common::{DataFusionError, Result as DFResult},
    logical_expr::Join,
    prelude::Column,
};
use datafusion_expr::{
    expr::WildcardOptions,
    logical_plan::builder::LogicalPlanBuilder,
    Expr,
    LogicalPlan,
    col,
    lit,
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

pub fn build_join_hint_generation_plans(
    plan: LogicalPlan,
) -> IndexMap<String, HintGenerationPlan> {
    let mut plans = IndexMap::new();
    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_string(), plan.clone()),
    );
    plans.extend(build_support_hint_plans(&plan));
    plans.extend(build_source_hint_plans(&plan));
    plans.insert(
        "output_key_support".to_string(),
        HintGenerationPlan::new_materialized(
            "output_key_support".to_string(),
            build_output_key_support_plan(&plan),
        ),
    );
    plans
}

pub fn build_verifier_join_hint_generation_plans(
    plan: LogicalPlan,
) -> IndexMap<String, HintGenerationPlan> {
    build_join_hint_generation_plans(plan)
}

fn build_support_hint_plans(plan: &LogicalPlan) -> IndexMap<String, HintGenerationPlan> {
    let join = match plan {
        LogicalPlan::Join(join) => join,
        other => panic!("expected join logical plan, found {:?}", other),
    };

    let mut support_plans = IndexMap::new();
    for (idx, (left_expr, right_expr)) in join.on.iter().enumerate() {
        let hint_name = format!("support_hints[{idx}]");
        let hint_plan =
            build_support_hint_plan_for_pair(plan, join, idx, left_expr, right_expr)
                .unwrap_or_else(|err| {
                    panic!(
                        "failed to build support hint plan for join equality {}: {}",
                        idx, err
                    )
                });
        support_plans.insert(
            hint_name.clone(),
            HintGenerationPlan::new_materialized(hint_name, hint_plan),
        );
    }

    support_plans
}

fn build_support_hint_plan_for_pair(
    plan: &LogicalPlan,
    join: &Join,
    idx: usize,
    left_expr: &Expr,
    right_expr: &Expr,
) -> DFResult<LogicalPlan> {
    let left_alias = format!("__truthtable_join_on{}_left_value", idx);
    let left_counts =
        build_value_count_plan(&(*join.left).clone(), left_expr, &left_alias)?;
    let left_support_plan = LogicalPlanBuilder::from(left_counts)
        .project(vec![
            lit("left_support").alias(SUPPORT_ROLE_COL),
            col(&left_alias).alias(SUPPORT_VALUE_COL),
            col(SUPPORT_COUNT_COL).alias(SUPPORT_COUNT_COL),
        ])?
        .build()?;

    let right_alias = format!("__truthtable_join_on{}_right_value", idx);
    let right_counts =
        build_value_count_plan(&(*join.right).clone(), right_expr, &right_alias)?;
    let right_support_plan = LogicalPlanBuilder::from(right_counts)
        .project(vec![
            lit("right_support").alias(SUPPORT_ROLE_COL),
            col(&right_alias).alias(SUPPORT_VALUE_COL),
            col(SUPPORT_COUNT_COL).alias(SUPPORT_COUNT_COL),
        ])?
        .build()?;

    let combined_alias = format!("__truthtable_join_on{}_output_value", idx);
    let output_counts = build_output_key_count_plan(join, left_expr, &combined_alias)?;
    let output_support_plan = LogicalPlanBuilder::from(output_counts)
        .project(vec![
            lit("output_support").alias(SUPPORT_ROLE_COL),
            col(&combined_alias).alias(SUPPORT_VALUE_COL),
            col(SUPPORT_COUNT_COL).alias(SUPPORT_COUNT_COL),
        ])?
        .build()?;

    LogicalPlanBuilder::from(left_support_plan)
        .union(right_support_plan)?
        .union(output_support_plan)?
        .build()
}

fn build_source_hint_plans(plan: &LogicalPlan) -> IndexMap<String, HintGenerationPlan> {
    let join = match plan {
        LogicalPlan::Join(join) => join,
        other => panic!("expected join logical plan, found {:?}", other),
    };

    let mut source_plans = IndexMap::new();
    for (idx, (left_expr, right_expr)) in join.on.iter().enumerate() {
        let hint_name = format!("source_hints[{idx}]");
        let hint_plan = build_source_hint_plan_for_pair(join, idx, left_expr, right_expr)
            .unwrap_or_else(|err| {
                panic!(
                    "failed to build source hint plan for join equality {}: {}",
                    idx, err
                )
            });
        source_plans.insert(
            hint_name.clone(),
            HintGenerationPlan::new_materialized(hint_name, hint_plan),
        );
    }

    source_plans
}

fn build_source_hint_plan_for_pair(
    join: &Join,
    idx: usize,
    left_expr: &Expr,
    right_expr: &Expr,
) -> DFResult<LogicalPlan> {
    let left_value_alias = format!("__truthtable_join_on{}_left_value", idx);
    let right_value_alias = format!("__truthtable_join_on{}_right_value", idx);
    let left_index_alias = format!("__truthtable_join_on{}_left_index", idx);
    let right_index_alias = format!("__truthtable_join_on{}_right_index", idx);

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

    let output_row_number_alias = format!("__truthtable_join_on{}_output_row_number", idx);
    let join_with_output_idx = LogicalPlanBuilder::from(join_plan)
        .window(vec![row_number().alias(output_row_number_alias.clone())])?
        .build()?;

    let left_projection = LogicalPlanBuilder::from(join_with_output_idx.clone())
        .project(vec![
            (col(&output_row_number_alias) - lit(1_i64)).alias(OUTPUT_INDEX_COL.to_string()),
            lit("left_source").alias(SOURCE_ROLE_COL),
            col(&left_index_alias).alias(SOURCE_INDEX_COL),
            col(&left_value_alias).alias(SOURCE_VALUE_COL),
        ])?
        .build()?;

    let right_projection = LogicalPlanBuilder::from(join_with_output_idx)
        .project(vec![
            (col(&output_row_number_alias) - lit(1_i64)).alias(OUTPUT_INDEX_COL.to_string()),
            lit("right_source").alias(SOURCE_ROLE_COL),
            col(&right_index_alias).alias(SOURCE_INDEX_COL),
            col(&right_value_alias).alias(SOURCE_VALUE_COL),
        ])?
        .build()?;

    LogicalPlanBuilder::from(left_projection)
        .union(right_projection)?
        .build()
}

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
            exprs.push(
                (col(&row_number_alias) - lit(1_i64)).alias(index_alias.to_string()),
            );
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
        panic!("failed to build output key support hint plan for join: {}", err)
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
