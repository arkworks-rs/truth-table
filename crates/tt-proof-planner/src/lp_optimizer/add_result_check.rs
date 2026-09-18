use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{Result, tree_node::Transformed};
use datafusion_expr::logical_plan::LogicalPlan;
use tt_core::irs::nodes::{
    plan::result_check::{self, ResultCheckLogicalNode},
    utils::result_check::ResultCheckMode,
};

#[derive(Debug, Default)]
pub(crate) struct AddResultCheck;

impl AddResultCheck {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl OptimizerRule for AddResultCheck {
    fn name(&self) -> &str {
        "add_result_check"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        None
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> Result<Transformed<LogicalPlan>> {
        // ResultCheck binds the one public table supplied to the final query
        // root. Subqueries are internal computations and have no independent
        // public OUTPUT payload. Wrapping them would create unverifiable nested
        // ResultChecks and would not strengthen the terminal statement.
        if let Some(existing) = result_check_node(&plan) {
            let required = terminal_result_mode(existing.input())?;
            if required == ResultCheckMode::Ordered && existing.mode() != ResultCheckMode::Ordered {
                return Err(datafusion_common::DataFusionError::Plan(
                    "an order-sensitive result is already wrapped in bag-only ResultCheck"
                        .to_string(),
                ));
            }
            Ok(Transformed::no(plan))
        } else {
            let mode = terminal_result_mode(&plan)?;
            Ok(Transformed::yes(result_check::wrap_logical_plan_with_mode(
                plan, mode,
            )))
        }
    }
}

/// Select the public-result relation from the terminal plan spine.
///
/// A top-level `Sort` makes row order observable. Projection, aliases, and
/// limits preserve that sequence, so they may occur between the public root
/// and the sort. Any other node ends the search: in particular, a sort inside
/// a join input or expression subquery must not change the outer result mode.
/// This deliberately conservative whitelist must be extended whenever the
/// planner learns another order-preserving terminal operator.
fn terminal_result_mode(plan: &LogicalPlan) -> Result<ResultCheckMode> {
    if terminal_spine_has_sort(plan) {
        Ok(ResultCheckMode::Ordered)
    } else if relational_plan_contains_sort(plan) {
        // A Sort exists, but an intervening relational operator is not in the
        // order-preserving whitelist. Choosing Bag would be a fail-open default
        // whenever a new terminal wrapper is introduced.
        Err(datafusion_common::DataFusionError::Plan(
            "cannot prove that the terminal plan preserves its ORDER BY sequence".to_string(),
        ))
    } else {
        Ok(ResultCheckMode::Bag)
    }
}

fn terminal_spine_has_sort(plan: &LogicalPlan) -> bool {
    match plan {
        LogicalPlan::Sort(_) => true,
        LogicalPlan::Projection(projection) => terminal_spine_has_sort(&projection.input),
        LogicalPlan::SubqueryAlias(alias) => terminal_spine_has_sort(&alias.input),
        // LIMIT/OFFSET select a subsequence without permuting it. Unsupported
        // offset forms still fail in the Limit reduction; marking the boundary
        // Ordered here prevents any future successful path from losing order.
        LogicalPlan::Limit(limit) => terminal_spine_has_sort(&limit.input),
        _ => false,
    }
}

fn relational_plan_contains_sort(plan: &LogicalPlan) -> bool {
    matches!(plan, LogicalPlan::Sort(_))
        || plan.inputs().into_iter().any(relational_plan_contains_sort)
}

#[cfg(test)]
fn is_result_check_plan(plan: &LogicalPlan) -> bool {
    result_check_node(plan).is_some()
}

fn result_check_node(plan: &LogicalPlan) -> Option<&ResultCheckLogicalNode> {
    let LogicalPlan::Extension(extension) = plan else {
        return None;
    };
    extension
        .node
        .as_any()
        .downcast_ref::<ResultCheckLogicalNode>()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::{
        arrow::datatypes::{DataType, Field, Schema},
        optimizer::{Optimizer, OptimizerContext, OptimizerRule},
        prelude::SessionContext,
    };
    use datafusion_common::Result;
    use datafusion_expr::{
        Expr, LogicalPlan, col,
        expr::InSubquery,
        logical_plan::{Subquery, builder::table_scan},
    };
    use tt_core::irs::nodes::{plan::result_check, utils::result_check::ResultCheckMode};

    use super::*;
    use crate::lp_optimizer::rules;

    #[test]
    fn optimizer_wraps_root_with_result_check() -> Result<()> {
        let session_ctx = SessionContext::new();
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, true)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .project(vec![Expr::Column("a".into())])?
            .build()?;

        let optimized = optimize_with_rules(plan, &session_ctx)?;
        assert!(is_result_check_plan(&optimized));
        assert_eq!(result_check_mode(&optimized), ResultCheckMode::Bag);
        Ok(())
    }

    #[test]
    fn optimizer_uses_ordered_check_for_terminal_sort() -> Result<()> {
        let session_ctx = SessionContext::new();
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, false)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .sort(vec![col("a").sort(true, true)])?
            .build()?;

        let optimized = optimize_with_rules(plan, &session_ctx)?;
        assert_eq!(result_check_mode(&optimized), ResultCheckMode::Ordered);
        Ok(())
    }

    #[test]
    fn projection_alias_and_limit_preserve_terminal_order() -> Result<()> {
        let session_ctx = SessionContext::new();
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, false)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .sort(vec![col("a").sort(false, false)])?
            .project(vec![col("a")])?
            .alias("ordered")?
            .limit(0, Some(3))?
            .build()?;

        let optimized = optimize_with_rules(plan, &session_ctx)?;
        assert_eq!(result_check_mode(&optimized), ResultCheckMode::Ordered);
        Ok(())
    }

    #[test]
    fn unknown_wrapper_above_sort_fails_closed() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, false)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .sort(vec![col("a").sort(true, true)])?
            .filter(
                col("a").gt(Expr::Literal(datafusion_common::ScalarValue::Int32(Some(
                    0,
                )))),
            )?
            .build()?;

        assert!(terminal_result_mode(&plan).is_err());
        Ok(())
    }

    #[test]
    fn existing_bag_wrapper_cannot_bypass_ordered_mode() -> Result<()> {
        let session_ctx = SessionContext::new();
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, false)]);
        let sorted = table_scan(Some("t"), &schema, None)?
            .sort(vec![col("a").sort(true, true)])?
            .build()?;
        let bag_wrapped = result_check::wrap_logical_plan(sorted);

        assert!(optimize_with_rules(bag_wrapped, &session_ctx).is_err());
        Ok(())
    }

    #[test]
    fn optimizer_keeps_result_check_as_outermost_node() -> Result<()> {
        let session_ctx = SessionContext::new();
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, true)]);
        let inner = table_scan(Some("t"), &schema, None)?.build()?;
        let plan = result_check::wrap_logical_plan(inner);

        let optimized = optimize_with_rules(plan, &session_ctx)?;
        let outer = match optimized {
            LogicalPlan::Extension(extension) => extension,
            other => panic!("expected result check extension, found {other:?}"),
        };
        assert!(outer.node.as_any().is::<ResultCheckLogicalNode>());

        let child = outer
            .node
            .inputs()
            .into_iter()
            .next()
            .expect("result check should have one input")
            .clone();
        assert!(
            !matches!(child, LogicalPlan::Extension(ref extension) if extension.node.as_any().is::<ResultCheckLogicalNode>()),
            "result check should remain the single outermost wrapper"
        );

        Ok(())
    }

    #[test]
    fn optimizer_does_not_wrap_internal_subqueries() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, true)]);
        let subquery_plan = table_scan(Some("inner"), &schema, None)?
            .project(vec![Expr::Column("a".into())])?
            .sort(vec![col("a").sort(true, true)])?
            .build()?;
        let predicate = Expr::InSubquery(InSubquery::new(
            Box::new(Expr::Column("a".into())),
            Subquery {
                subquery: Arc::new(subquery_plan),
                outer_ref_columns: vec![],
            },
            false,
        ));
        let plan = table_scan(Some("outer"), &schema, None)?
            .filter(predicate)?
            .build()?;

        // Exercise AddResultCheck in isolation so DataFusion does not first
        // decorrelate the subquery into a join and hide this regression.
        let optimizer = Optimizer::with_rules(vec![Arc::new(AddResultCheck::new())]);
        let config = OptimizerContext::new().with_max_passes(16);
        let optimized = optimizer.optimize(plan, &config, |_plan_after_rule, _rule| {})?;
        let root = match optimized {
            LogicalPlan::Extension(extension) => extension,
            other => panic!("expected terminal result check, found {other:?}"),
        };
        assert!(root.node.as_any().is::<ResultCheckLogicalNode>());
        assert_eq!(
            root.node
                .as_any()
                .downcast_ref::<ResultCheckLogicalNode>()
                .expect("result check node")
                .mode(),
            ResultCheckMode::Bag,
            "a sort inside an expression subquery must not order the outer result"
        );

        let inputs = root.node.inputs();
        let Some(LogicalPlan::Filter(filter)) = inputs.first().copied() else {
            panic!("expected filter below terminal ResultCheck")
        };
        let Expr::InSubquery(in_subquery) = &filter.predicate else {
            panic!("expected IN subquery predicate")
        };
        assert!(
            !is_result_check_plan(in_subquery.subquery.subquery.as_ref()),
            "an internal subquery has no independent public OUTPUT payload"
        );
        Ok(())
    }

    fn optimize_with_rules(plan: LogicalPlan, session_ctx: &SessionContext) -> Result<LogicalPlan> {
        let optimizer_rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = rules(session_ctx);
        let optimizer = Optimizer::with_rules(optimizer_rules);
        let config = OptimizerContext::new().with_max_passes(16);
        optimizer.optimize(plan, &config, |_plan_after_rule, _rule| {})
    }

    fn result_check_mode(plan: &LogicalPlan) -> ResultCheckMode {
        let LogicalPlan::Extension(extension) = plan else {
            panic!("expected terminal ResultCheck, found {plan:?}")
        };
        extension
            .node
            .as_any()
            .downcast_ref::<ResultCheckLogicalNode>()
            .expect("ResultCheck logical node")
            .mode()
    }
}
