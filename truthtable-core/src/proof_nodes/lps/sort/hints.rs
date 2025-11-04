use crate::proof_nodes::{HintGenerationPlan, OUTPUT_PLAN_KEY};
use datafusion::logical_expr::{
    self as df,
    expr_rewriter::{normalize_sorts, unnormalize_col},
};
use datafusion_expr::{LogicalPlan, LogicalPlanBuilder, expr::Sort as DFSortExpr};
use indexmap::IndexMap;

pub(super) const LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY: &str = "__lex_sort_expressions__";
pub(super) const SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY: &str =
    "__shifted_lex_sort_expressions__";
pub(super) const TIE_INDICATOR_PLAN_KEY: &str = "__tie_indicators__";
pub(super) fn build_sort_hint_generation_plans(
    base_plan: LogicalPlan,
    sort_plan: &datafusion_expr::logical_plan::Sort,
) -> IndexMap<String, HintGenerationPlan> {
    let normalized_sorts = normalize_sort_expressions(sort_plan, &base_plan);

    let sort_expr_plan = build_sorted_plan(base_plan, sort_plan, &normalized_sorts);
    let sorted_output_plan = project_sorted_output_plan(&sort_expr_plan);
    let lex_sorted_sort_expressions_plan =
        build_lex_sorted_sort_exprs_plan(&sort_expr_plan, &normalized_sorts);
    let shifted_lex_sorted_sort_expressions_plan =
        build_shifted_lex_sorted_sort_exprs_plan(&lex_sorted_sort_expressions_plan);
    let tie_indicator_plan =
        build_tie_indicator_plan(&lex_sorted_sort_expressions_plan, normalized_sorts.len());

    let mut plans = IndexMap::new();
    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(OUTPUT_PLAN_KEY.to_string(), sorted_output_plan),
    );
    plans.insert(
        super::LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(
            super::LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY.to_string(),
            lex_sorted_sort_expressions_plan.clone(),
        ),
    );
    plans.insert(
        super::SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY.to_string(),
        HintGenerationPlan::new_materialized(
            super::SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY.to_string(),
            shifted_lex_sorted_sort_expressions_plan,
        ),
    );
    if let Some(tie_plan) = tie_indicator_plan {
        plans.insert(
            super::TIE_INDICATOR_PLAN_KEY.to_string(),
            HintGenerationPlan::new_materialized(
                super::TIE_INDICATOR_PLAN_KEY.to_string(),
                tie_plan,
            ),
        );
    }

    plans
}

fn normalize_sort_expressions(
    sort_plan: &datafusion_expr::logical_plan::Sort,
    base_plan: &LogicalPlan,
) -> Vec<DFSortExpr> {
    normalize_sorts(sort_plan.expr.clone(), base_plan)
        .expect("failed to normalize sort expressions for hint plan")
        .into_iter()
        .map(|sort_expr| {
            let expr = unnormalize_col(sort_expr.expr);
            DFSortExpr::new(expr, sort_expr.asc, sort_expr.nulls_first)
        })
        .collect()
}

fn build_sorted_plan(
    base_plan: LogicalPlan,
    sort_plan: &datafusion_expr::logical_plan::Sort,
    normalized_sorts: &[DFSortExpr],
) -> LogicalPlan {
    LogicalPlanBuilder::from(base_plan)
        .sort_with_limit(normalized_sorts.to_vec(), sort_plan.fetch)
        .expect("failed to append sort for hint plan")
        .build()
        .expect("failed to build sorted hint plan")
}

fn project_sorted_output_plan(sorted_plan: &LogicalPlan) -> LogicalPlan {
    let projection_exprs: Vec<df::Expr> = sorted_plan
        .schema()
        .iter()
        .map(|(qualifier, field)| df::Expr::from((qualifier, field)))
        .collect();

    LogicalPlanBuilder::from(sorted_plan.clone())
        .project(projection_exprs)
        .expect("failed to project sorted columns for hint plan")
        .build()
        .expect("failed to build sorted projected hint plan")
}

fn build_lex_sorted_sort_exprs_plan(
    sorted_plan: &LogicalPlan,
    normalized_sorts: &[DFSortExpr],
) -> LogicalPlan {
    let sort_projection_exprs: Vec<df::Expr> = normalized_sorts
        .iter()
        .map(|sort_expr| sort_expr.expr.clone())
        .collect();

    LogicalPlanBuilder::from(sorted_plan.clone())
        .project(sort_projection_exprs)
        .expect("failed to project sort expressions for hint plan")
        .build()
        .expect("failed to build sort expressions hint plan")
}

fn build_shifted_lex_sorted_sort_exprs_plan(sort_expressions_plan: &LogicalPlan) -> LogicalPlan {
    // Skip the first row so row i becomes row i+1 for i >= 0
    let tail_plan = LogicalPlanBuilder::from(sort_expressions_plan.clone())
        .limit(1, None)
        .expect("failed to skip first row for shifted sort expressions plan")
        .build()
        .expect("failed to build shifted tail plan");

    // Capture the first row so it can wrap around to the end
    let head_plan = LogicalPlanBuilder::from(sort_expressions_plan.clone())
        .limit(0, Some(1))
        .expect("failed to limit first row for shifted sort expressions plan")
        .build()
        .expect("failed to build shifted head plan");

    LogicalPlanBuilder::from(tail_plan)
        .union(head_plan)
        .expect("failed to union shifted sort expression parts")
        .build()
        .expect("failed to build shifted sort expressions plan")
}

fn build_tie_indicator_plan(
    sort_expressions_plan: &LogicalPlan,
    num_sort_exprs: usize,
) -> Option<LogicalPlan> {
    if num_sort_exprs <= 1 {
        return None;
    }

    let tie_projection_exprs: Vec<df::Expr> = (0..(num_sort_exprs - 1))
        .map(|idx| df::lit(false).alias(format!("tie_indicator_{idx}")))
        .collect();

    Some(
        LogicalPlanBuilder::from(sort_expressions_plan.clone())
            .project(tie_projection_exprs)
            .expect("failed to project tie indicator expressions for hint plan")
            .build()
            .expect("failed to build tie indicator hint plan"),
    )
}
