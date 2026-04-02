use std::sync::Arc;

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::tree_node::Transformed;
use datafusion_expr::logical_plan::{Filter, LogicalPlan};

#[derive(Debug, Default)]
pub(crate) struct MergeConsecutiveFilters;

impl MergeConsecutiveFilters {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl OptimizerRule for MergeConsecutiveFilters {
    fn name(&self) -> &str {
        "merge_consecutive_filters"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        Some(ApplyOrder::BottomUp)
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> datafusion_common::Result<Transformed<LogicalPlan>> {
        plan.transform_up_with_subqueries(merge_filters)
    }
}

fn merge_filters(plan: LogicalPlan) -> datafusion_common::Result<Transformed<LogicalPlan>> {
    let LogicalPlan::Filter(outer) = plan else {
        return Ok(Transformed::no(plan));
    };

    let LogicalPlan::Filter(inner) = outer.input.as_ref() else {
        return Ok(Transformed::no(LogicalPlan::Filter(outer)));
    };

    let merged_predicate = if outer.predicate == inner.predicate {
        outer.predicate.clone()
    } else {
        outer.predicate.clone().and(inner.predicate.clone())
    };
    let merged = Filter::try_new(merged_predicate, Arc::clone(&inner.input))?;
    Ok(Transformed::yes(LogicalPlan::Filter(merged)))
}
