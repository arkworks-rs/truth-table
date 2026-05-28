use std::sync::Arc;

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{
    Result,
    tree_node::{Transformed, TreeNode, TreeNodeRecursion},
};
use datafusion_expr::{
    Expr,
    expr::{Exists, InSubquery},
    logical_plan::{LogicalPlan, Subquery},
};
use tt_core::irs::nodes::plan::result_check::{self, ResultCheckLogicalNode};

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
        let transformed_subqueries = plan.map_expressions(rewrite_subqueries_with_result_check)?;
        let plan = transformed_subqueries.data;
        if is_result_check_plan(&plan) {
            Ok(Transformed::new(
                plan,
                transformed_subqueries.transformed,
                TreeNodeRecursion::Continue,
            ))
        } else {
            Ok(Transformed::yes(result_check::wrap_logical_plan(plan)))
        }
    }
}

fn rewrite_subqueries_with_result_check(expr: Expr) -> Result<Transformed<Expr>> {
    expr.transform_up(|expr| match expr {
        Expr::ScalarSubquery(Subquery {
            subquery,
            outer_ref_columns,
        }) => Ok(Transformed::yes(Expr::ScalarSubquery(Subquery {
            subquery: Arc::new(add_result_check(Arc::unwrap_or_clone(subquery))?),
            outer_ref_columns,
        }))),
        Expr::Exists(Exists { subquery, negated }) => Ok(Transformed::yes(Expr::Exists(Exists {
            subquery: Subquery {
                subquery: Arc::new(add_result_check(Arc::unwrap_or_clone(subquery.subquery))?),
                outer_ref_columns: subquery.outer_ref_columns,
            },
            negated,
        }))),
        Expr::InSubquery(InSubquery {
            expr: input_expr,
            subquery,
            negated,
        }) => Ok(Transformed::yes(Expr::InSubquery(InSubquery::new(
            input_expr,
            Subquery {
                subquery: Arc::new(add_result_check(Arc::unwrap_or_clone(subquery.subquery))?),
                outer_ref_columns: subquery.outer_ref_columns,
            },
            negated,
        )))),
        other => Ok(Transformed::no(other)),
    })
}

fn add_result_check(plan: LogicalPlan) -> Result<LogicalPlan> {
    let plan = plan
        .map_expressions(rewrite_subqueries_with_result_check)?
        .data;
    if is_result_check_plan(&plan) {
        Ok(plan)
    } else {
        Ok(result_check::wrap_logical_plan(plan))
    }
}

fn is_result_check_plan(plan: &LogicalPlan) -> bool {
    matches!(
        plan,
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<ResultCheckLogicalNode>()
    )
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
    use datafusion_expr::{Expr, LogicalPlan, logical_plan::builder::table_scan};
    use tt_core::irs::nodes::plan::result_check;

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

    fn optimize_with_rules(plan: LogicalPlan, session_ctx: &SessionContext) -> Result<LogicalPlan> {
        let optimizer_rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = rules(session_ctx);
        let optimizer = Optimizer::with_rules(optimizer_rules);
        let config = OptimizerContext::new().with_max_passes(16);
        optimizer.optimize(plan, &config, |_plan_after_rule, _rule| {})
    }
}
