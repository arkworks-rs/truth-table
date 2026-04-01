use std::sync::Arc;

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{
    DataFusionError, Result as DataFusionResult,
    tree_node::Transformed,
};
use datafusion_expr::{
    Expr,
    logical_plan::{Limit, LogicalPlan},
};

#[derive(Debug, Default)]
pub(crate) struct NormalizeSortFetch;

impl NormalizeSortFetch {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl OptimizerRule for NormalizeSortFetch {
    fn name(&self) -> &str {
        "normalize_sort_fetch"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        Some(ApplyOrder::BottomUp)
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> DataFusionResult<Transformed<LogicalPlan>> {
        plan.transform_up_with_subqueries(normalize_plan_node)
    }
}

fn normalize_plan_node(plan: LogicalPlan) -> DataFusionResult<Transformed<LogicalPlan>> {
    let LogicalPlan::Sort(mut sort) = plan else {
        return Ok(Transformed::no(plan));
    };

    let Some(fetch) = sort.fetch.take() else {
        return Ok(Transformed::no(LogicalPlan::Sort(sort)));
    };

    // Our proof pipeline models a full sort as a permutation and a top-k as a
    // separate limit mask. Rewriting `Sort(fetch = k)` into `Sort + Limit(k)`
    // keeps the sort proof shape unchanged and lets the existing Limit gadget
    // handle the truncation.
    let fetch_i64 = i64::try_from(fetch).map_err(|_| {
        DataFusionError::Execution(format!("sort fetch {fetch} does not fit into i64"))
    })?;
    let fetch_expr = Expr::Literal(datafusion_common::ScalarValue::Int64(Some(fetch_i64)));
    let limit = Limit {
        skip: None,
        fetch: Some(Box::new(fetch_expr)),
        input: Arc::new(LogicalPlan::Sort(sort)),
    };

    Ok(Transformed::yes(LogicalPlan::Limit(limit)))
}
