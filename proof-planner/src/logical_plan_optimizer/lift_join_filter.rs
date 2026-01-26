use std::sync::Arc;

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::tree_node::Transformed;
use datafusion_expr::logical_plan::{Filter, Join, JoinType, LogicalPlan};
use tracing::debug;

#[derive(Debug, Default)]
pub(crate) struct LiftJoinFilter;

impl LiftJoinFilter {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl OptimizerRule for LiftJoinFilter {
    fn name(&self) -> &str {
        "lift_join_filter"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        Some(ApplyOrder::BottomUp)
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> datafusion_common::Result<Transformed<LogicalPlan>> {
        plan.transform_up_with_subqueries(lift_join_filter)
    }
}

fn lift_join_filter(plan: LogicalPlan) -> datafusion_common::Result<Transformed<LogicalPlan>> {
    let LogicalPlan::Join(mut join) = plan else {
        return Ok(Transformed::no(plan));
    };

    if join.join_type != JoinType::Inner {
        return Ok(Transformed::no(LogicalPlan::Join(join)));
    }

    let Some(filter) = join.filter.take() else {
        return Ok(Transformed::no(LogicalPlan::Join(join)));
    };

    debug!("LiftJoinFilter applied: filter moved to separate Filter node");
    let join_plan = LogicalPlan::Join(Join { filter: None, ..join });
    let filter_plan = LogicalPlan::Filter(Filter::try_new(filter, Arc::new(join_plan))?);
    Ok(Transformed::yes(filter_plan))
}
