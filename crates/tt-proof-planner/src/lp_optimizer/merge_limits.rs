use std::sync::Arc;

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{ScalarValue, tree_node::Transformed};
use datafusion_expr::{
    Expr,
    logical_plan::{Limit, LogicalPlan},
};

#[derive(Debug, Default)]
pub(crate) struct MergeConsecutiveLimits;

impl MergeConsecutiveLimits {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl OptimizerRule for MergeConsecutiveLimits {
    fn name(&self) -> &str {
        "merge_consecutive_limits"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        Some(ApplyOrder::BottomUp)
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> datafusion_common::Result<Transformed<LogicalPlan>> {
        plan.transform_up_with_subqueries(merge_limits)
    }
}

// `PushDownLimit` keeps an explicit `Limit` above a `Projection` and also
// annotates the underlying `TableScan` with `fetch=Some(...)`. The downstream
// `NormalizeTableScanPushdown` rule re-materialises that fetch into a new
// `Limit` directly above the scan, leaving two back-to-back `Limit`s with
// identical bounds. This rule collapses them.

// `None` skip is treated as zero; `None` fetch is "no upper bound" (i64::MAX).
// Returns `None` for non-literal expressions, in which case merging bails out.
fn skip_value(skip: &Option<Box<Expr>>) -> Option<i64> {
    match skip {
        None => Some(0),
        Some(expr) => match expr.as_ref() {
            Expr::Literal(ScalarValue::Int64(Some(v))) => Some(*v),
            _ => None,
        },
    }
}

fn fetch_value(fetch: &Option<Box<Expr>>) -> Option<i64> {
    match fetch {
        None => Some(i64::MAX),
        Some(expr) => match expr.as_ref() {
            Expr::Literal(ScalarValue::Int64(Some(v))) => Some(*v),
            _ => None,
        },
    }
}

fn merge_limits(plan: LogicalPlan) -> datafusion_common::Result<Transformed<LogicalPlan>> {
    let LogicalPlan::Limit(outer) = plan else {
        return Ok(Transformed::no(plan));
    };

    let LogicalPlan::Limit(inner) = outer.input.as_ref() else {
        return Ok(Transformed::no(LogicalPlan::Limit(outer)));
    };

    let (Some(outer_skip), Some(inner_skip), Some(outer_fetch), Some(inner_fetch)) = (
        skip_value(&outer.skip),
        skip_value(&inner.skip),
        fetch_value(&outer.fetch),
        fetch_value(&inner.fetch),
    ) else {
        return Ok(Transformed::no(LogicalPlan::Limit(outer)));
    };

    // Only collapse when the two limits are semantically equal. The case in
    // practice is `Limit(skip=0, fetch=N) -> Limit(skip=0, fetch=N)` produced
    // when `PushDownLimit` keeps an explicit Limit *and* annotates the
    // underlying `TableScan.fetch`, which `NormalizeTableScanPushdown` then
    // re-materialises. Generalising to unequal bounds would require correct
    // skip/fetch arithmetic and isn't needed to fix the regression.
    if outer_skip != inner_skip || outer_fetch != inner_fetch {
        return Ok(Transformed::no(LogicalPlan::Limit(outer)));
    }

    let merged = Limit {
        skip: outer.skip,
        fetch: outer.fetch,
        input: Arc::clone(&inner.input),
    };
    Ok(Transformed::yes(LogicalPlan::Limit(merged)))
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
    use datafusion_common::tree_node::TreeNode;
    use datafusion_expr::{Expr, LogicalPlan, logical_plan::builder::table_scan};

    use crate::lp_optimizer::rules;

    fn count_limits(plan: &LogicalPlan) -> usize {
        let mut n = 0;
        plan.apply(|node| {
            if matches!(node, LogicalPlan::Limit(_)) {
                n += 1;
            }
            Ok(datafusion_common::tree_node::TreeNodeRecursion::Continue)
        })
        .unwrap();
        n
    }

    #[test]
    fn optimizer_collapses_redundant_limit_pair() -> Result<()> {
        let session_ctx = SessionContext::new();
        let schema = Schema::new(vec![Field::new("column", DataType::Int32, true)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .project(vec![Expr::Column("column".into())])?
            .limit(0, Some(10))?
            .build()?;

        let optimizer_rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = rules(&session_ctx);
        let optimizer = Optimizer::with_rules(optimizer_rules);
        let config = OptimizerContext::new().with_max_passes(16);
        let optimized = optimizer.optimize(plan, &config, |_plan_after_rule, _rule| {})?;
        assert_eq!(
            count_limits(&optimized),
            1,
            "expected a single Limit after optimization, got plan: {}",
            optimized.display_indent()
        );
        Ok(())
    }
}
