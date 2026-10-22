use std::sync::Arc;

use add_result_check::AddResultCheck;

use datafusion::{
    optimizer::{
        OptimizerRule, common_subexpr_eliminate::CommonSubexprEliminate,
        eliminate_cross_join::EliminateCrossJoin,
        eliminate_duplicated_expr::EliminateDuplicatedExpr, eliminate_filter::EliminateFilter,
        eliminate_group_by_constant::EliminateGroupByConstant, eliminate_join::EliminateJoin,
        eliminate_limit::EliminateLimit, eliminate_nested_union::EliminateNestedUnion,
        eliminate_one_union::EliminateOneUnion,
        extract_equijoin_predicate::ExtractEquijoinPredicate,
        propagate_empty_relation::PropagateEmptyRelation, push_down_limit::PushDownLimit,
        scalar_subquery_to_join::ScalarSubqueryToJoin, simplify_expressions::SimplifyExpressions,
    },
    prelude::SessionContext,
};

mod add_result_check;
mod customized_optimize_projections;
mod fetch_safe_push_down_filter;
pub use fetch_safe_push_down_filter::FetchSafePushDownFilter;
mod lift_join_filter;
mod like_prefilter;
pub use like_prefilter::insert_like_prefilters;
mod merge_filters;
mod merge_limits;
mod normalize_sort_fetch;
mod normalize_table_scan;

pub fn rules(_session_ctx: &SessionContext) -> Vec<Arc<dyn OptimizerRule + Send + Sync>> {
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
        // A LEFT join under a filter that rejects NULLs from its right side
        // (decorrelated scalar subqueries, TPC-H Q2 and Q17) is an INNER join;
        // the join protocols prove inner joins only.
        Arc::new(datafusion::optimizer::eliminate_outer_join::EliminateOuterJoin::new()),
        // Filters can't be pushed down past Limits, we should do PushDownFilter after PushDownLimit
        Arc::new(PushDownLimit::new()),
        Arc::new(FetchSafePushDownFilter::new()),
        // The previous optimizations added expressions and projections,
        // that might benefit from the following rules
        Arc::new(SimplifyExpressions::new()),
        Arc::new(EliminateGroupByConstant::new()),
        Arc::new(normalize_table_scan::NormalizeTableScanPushdown::new()),
        Arc::new(merge_limits::MergeConsecutiveLimits::new()),
        Arc::new(normalize_sort_fetch::NormalizeSortFetch::new()),
        Arc::new(merge_filters::MergeConsecutiveFilters::new()),
        Arc::new(lift_join_filter::LiftJoinFilter::new()),
        Arc::new(customized_optimize_projections::OptimizeProjections::new()),
        // Compaction is not in this list: it is data-dependent, so the prover
        // emits hints and the verifier replays them.
        Arc::new(AddResultCheck::new()),
    ]
}
