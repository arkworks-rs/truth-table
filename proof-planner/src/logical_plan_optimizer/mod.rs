use std::sync::Arc;

use datafusion::{
    optimizer::{
        eliminate_cross_join::EliminateCrossJoin,
        extract_equijoin_predicate::ExtractEquijoinPredicate, push_down_filter::PushDownFilter,
        simplify_expressions::SimplifyExpressions, OptimizerRule,
    },
    prelude::SessionContext,
};

mod normalize_table_scan;
mod rematerialize;
mod lift_join_filter;

// pub(crate) fn optimize_logical_plan(plan: LogicalPlan) -> LogicalPlan {
//     let rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = vec![
//         Arc::new(ExtractEquijoinPredicate),
//         Arc::new(EliminateCrossJoin),
//     ];

//     let optimizer = Optimizer::with_rules(rules);

//     let config = OptimizerContext::new().with_max_passes(16);

//     optimizer.optimize(plan.clone(), &config, observer).unwrap()
// }
// fn observer(_plan: &LogicalPlan, _rule: &dyn OptimizerRule) {}

pub fn rules(session_ctx: &SessionContext) -> Vec<Arc<dyn OptimizerRule + Send + Sync>> {
    vec![
        Arc::new(ExtractEquijoinPredicate),
        Arc::new(EliminateCrossJoin),
        Arc::new(SimplifyExpressions::new()),
        Arc::new(PushDownFilter::new()),
        Arc::new(normalize_table_scan::NormalizeTableScanPushdown::new()),
        Arc::new(lift_join_filter::LiftJoinFilter::new()),
        // Arc::new(rematerialize::RematerializeRule::new(session_ctx.state())),
    ]
}
