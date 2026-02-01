use std::sync::Arc;

use datafusion::{
    optimizer::{
        common_subexpr_eliminate::CommonSubexprEliminate, eliminate_cross_join::EliminateCrossJoin,
        eliminate_duplicated_expr::EliminateDuplicatedExpr, eliminate_filter::EliminateFilter,
        eliminate_group_by_constant::EliminateGroupByConstant, eliminate_join::EliminateJoin,
        eliminate_limit::EliminateLimit, eliminate_nested_union::EliminateNestedUnion,
        eliminate_one_union::EliminateOneUnion,
        extract_equijoin_predicate::ExtractEquijoinPredicate,
        optimize_projections::OptimizeProjections,
        propagate_empty_relation::PropagateEmptyRelation, push_down_filter::PushDownFilter,
        push_down_limit::PushDownLimit, scalar_subquery_to_join::ScalarSubqueryToJoin,
        simplify_expressions::SimplifyExpressions, OptimizerRule,
    },
    prelude::SessionContext,
};

mod customized_optimize_projections;
mod lift_join_filter;
mod merge_filters;
mod normalize_table_scan;
mod rematerialize;
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
        Arc::new(EliminateNestedUnion::new()),
        Arc::new(SimplifyExpressions::new()),
        Arc::new(EliminateJoin::new()),
        Arc::new(ScalarSubqueryToJoin::new()),
        Arc::new(ExtractEquijoinPredicate::new()),
        Arc::new(EliminateDuplicatedExpr::new()),
        Arc::new(EliminateFilter::new()),
        Arc::new(EliminateCrossJoin::new()),
        Arc::new(CommonSubexprEliminate::new()),
        Arc::new(EliminateLimit::new()),
        Arc::new(PropagateEmptyRelation::new()),
        // Must be after PropagateEmptyRelation
        Arc::new(EliminateOneUnion::new()),
        // Filters can't be pushed down past Limits, we should do PushDownFilter after PushDownLimit
        Arc::new(PushDownLimit::new()),
        Arc::new(PushDownFilter::new()),
        // The previous optimizations added expressions and projections,
        // that might benefit from the following rules
        Arc::new(SimplifyExpressions::new()),
        // Arc::new(CommonSubexprEliminate::new()),
        Arc::new(EliminateGroupByConstant::new()),
        Arc::new(normalize_table_scan::NormalizeTableScanPushdown::new()),
        Arc::new(merge_filters::MergeConsecutiveFilters::new()),
        Arc::new(lift_join_filter::LiftJoinFilter::new()),
        Arc::new(customized_optimize_projections::OptimizeProjections::new()),
        Arc::new(rematerialize::RematerializeRule::new(session_ctx.state())),
    ]
}
