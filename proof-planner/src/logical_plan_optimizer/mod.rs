use std::sync::Arc;

use datafusion::{
    logical_expr::LogicalPlan,
    optimizer::{Optimizer, OptimizerContext, OptimizerRule},
};

pub(crate) fn optimize_logical_plan(plan: LogicalPlan) -> LogicalPlan {
    let rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = vec![];

    let optimizer = Optimizer::with_rules(rules);

    let config = OptimizerContext::new().with_max_passes(16);

    optimizer.optimize(plan.clone(), &config, observer).unwrap()
}
fn observer(plan: &LogicalPlan, rule: &dyn OptimizerRule) {}
