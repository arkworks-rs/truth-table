use std::sync::Arc;

use datafusion::{
    logical_expr::LogicalPlan,
    optimizer::{
        common_subexpr_eliminate::CommonSubexprEliminate,
        decorrelate_predicate_subquery::DecorrelatePredicateSubquery,
        eliminate_cross_join::EliminateCrossJoin,
        eliminate_duplicated_expr::EliminateDuplicatedExpr, eliminate_filter::EliminateFilter,
        eliminate_join::EliminateJoin, eliminate_limit::EliminateLimit,
        eliminate_outer_join::EliminateOuterJoin,
        extract_equijoin_predicate::ExtractEquijoinPredicate, push_down_filter::PushDownFilter,
        push_down_limit::PushDownLimit, replace_distinct_aggregate::ReplaceDistinctWithAggregate,
        scalar_subquery_to_join::ScalarSubqueryToJoin, simplify_expressions::SimplifyExpressions,
        single_distinct_to_groupby::SingleDistinctToGroupBy, Optimizer, OptimizerContext,
        OptimizerRule,
    },
};

pub(crate) fn optimize_logical_plan(plan: LogicalPlan) -> LogicalPlan {
    let rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = vec![
        // Arc::new(EliminateNestedUnion::new()),
        // Arc::new(SimplifyExpressions::new()),
        // Arc::new(UnwrapCastInComparison::new()),
        // Arc::new(EliminateDuplicatedExpr::new()),
        // Arc::new(CommonSubexprEliminate::new()),
        // Arc::new(PropagateEmptyRelation::new()),
        // Must be after PropagateEmptyRelation
        // Arc::new(EliminateOneUnion::new()),
        // Arc::new(FilterNullJoinKeys::default()),
        // Filters can't be pushed down past Limits, we should do PushDownFilter after
        // PushDownLimit

        // The previous optimizations added expressions and projections,
        // that might benefit from the following rules
        // Arc::new(SimplifyExpressions::new()),
        // Arc::new(UnwrapCastInComparison::new()),
        // Arc::new(CommonSubexprEliminate::new()),
        // Arc::new(EliminateGroupByConstant::new()),
        // Arc::new(OptimizeProjections::new()),
    ];

    let optimizer = Optimizer::with_rules(rules);

    let config = OptimizerContext::new().with_max_passes(16);

    optimizer.optimize(plan.clone(), &config, observer).unwrap()
}
fn observer(plan: &LogicalPlan, rule: &dyn OptimizerRule) {}
