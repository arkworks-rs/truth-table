use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{Result, tree_node::Transformed};
use datafusion_expr::logical_plan::LogicalPlan;
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
        // ResultCheck binds the one public table supplied to the final query
        // root. Subqueries are internal computations and have no independent
        // public OUTPUT payload. Wrapping them would create unverifiable nested
        // ResultChecks and would not strengthen the terminal statement.
        if is_result_check_plan(&plan) {
            Ok(Transformed::no(plan))
        } else {
            Ok(Transformed::yes(result_check::wrap_logical_plan(plan)))
        }
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
    use datafusion_expr::{
        Expr, LogicalPlan,
        expr::InSubquery,
        logical_plan::{Subquery, builder::table_scan},
    };
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

    #[test]
    fn optimizer_does_not_wrap_internal_subqueries() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, true)]);
        let subquery_plan = table_scan(Some("inner"), &schema, None)?
            .project(vec![Expr::Column("a".into())])?
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
}
