use arithmetic::ACTIVATOR_COL_NAME;
use crate::proof_nodes::{HintGenerationPlan, OUTPUT_PLAN_KEY};
use datafusion::{
    common::{DataFusionError, Result, ScalarValue},
    logical_expr::{
        self as df,
        expr_rewriter::{normalize_sorts, unnormalize_col},
    },
};
use datafusion_expr::{
    col,
    expr::Sort as DFSortExpr,
    expr_fn::binary_expr,
    lit,
    Expr,
    ExprFunctionExt,
    LogicalPlan,
    LogicalPlanBuilder,
    Operator,
    Sort,
};
use datafusion_functions_window::expr_fn::lead;
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
        build_tie_indicator_plan(&sort_expr_plan, normalized_sorts.len());

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
    let mut projection_exprs: Vec<df::Expr> = normalized_sorts
        .iter()
        .map(|sort_expr| sort_expr.expr.clone())
        .collect();

    if sorted_plan
        .schema()
        .field_with_unqualified_name(ACTIVATOR_COL_NAME)
        .is_ok()
    {
        projection_exprs.push(df::col(ACTIVATOR_COL_NAME));
    }

    LogicalPlanBuilder::from(sorted_plan.clone())
        .project(projection_exprs)
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

/// Build a plan that emits `tie_1 .. tie_{num_sort_exprs-1}` as booleans.
/// `sort_expressions_plan` must be a top-level LogicalPlan::Sort.
/// Each tie_i(j) is true iff the prefix of i ORDER BY expressions at row j
/// IS NOT DISTINCT FROM the same prefix at row j+1.
pub fn build_tie_indicator_plan(
    sort_expressions_plan: &LogicalPlan,
    num_sort_exprs: usize,
) -> Option<LogicalPlan> {
    build_tie_indicator_plan_impl(sort_expressions_plan, num_sort_exprs)
        .ok()
        .flatten()
}

fn build_tie_indicator_plan_impl(
    sort_plan: &LogicalPlan,
    num_sort_exprs: usize,
) -> Result<Option<LogicalPlan>> {
    let order_by_exprs = match sort_plan {
        LogicalPlan::Sort(Sort { expr, .. }) => expr.clone(),
        _ => {
            return Err(DataFusionError::Plan(
                "build_tie_indicator_plan expects a top-level Sort plan".into(),
            ));
        },
    };

    if num_sort_exprs <= 1 {
        return Ok(None);
    }

    if num_sort_exprs > order_by_exprs.len() {
        return Err(DataFusionError::Plan(format!(
            "num_sort_exprs ({}) exceeds number of ORDER BY expressions ({})",
            num_sort_exprs,
            order_by_exprs.len()
        )));
    }

    let mut window_exprs: Vec<Expr> = Vec::with_capacity(num_sort_exprs + 1);
    let order_by_clone = order_by_exprs.clone();

    for (index, sort_expr) in order_by_exprs.iter().take(num_sort_exprs).enumerate() {
        let alias = next_alias(index);
        let lead_expr = lead(sort_expr.expr.clone(), Some(1), None)
            .order_by(order_by_clone.clone())
            .build()?
            .alias(&alias);
        window_exprs.push(lead_expr);
    }

    const HAS_NEXT_ALIAS: &str = "__has_next_row__";
    let has_next_expr = lead(lit(true), Some(1), Some(ScalarValue::Boolean(Some(false))))
        .order_by(order_by_exprs.clone())
        .build()?
        .alias(HAS_NEXT_ALIAS);
    window_exprs.push(has_next_expr);

    let with_window = LogicalPlanBuilder::from(sort_plan.clone())
        .window(window_exprs)?
        .build()?;

    let mut tie_cols: Vec<Expr> = Vec::with_capacity(num_sort_exprs - 1);
    for i in 1..num_sort_exprs {
        let mut predicates: Vec<Expr> = Vec::with_capacity(i);
        for k in 0..i {
            let lhs = order_by_exprs[k].expr.clone();
            let rhs = col(&next_alias(k));
            predicates.push(binary_expr(lhs, Operator::IsNotDistinctFrom, rhs));
        }
        let prefix_match = and_all(predicates);
        let tie_expr = col(HAS_NEXT_ALIAS)
            .and(prefix_match)
            .alias(&format!("tie_{}", i));
        tie_cols.push(tie_expr);
    }

    let projected = LogicalPlanBuilder::from(with_window)
        .project(tie_cols)?
        .build()?;

    Ok(Some(projected))
}

fn next_alias(k: usize) -> String {
    format!("__next_ord_{}", k)
}

fn and_all(mut exprs: Vec<Expr>) -> Expr {
    assert!(!exprs.is_empty());
    let mut it = exprs.drain(..);
    let mut acc = it.next().unwrap();
    for e in it {
        acc = acc.and(e);
    }
    acc
}
