use std::{mem, sync::Arc};

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{
    tree_node::Transformed, DataFusionError, Result as DataFusionResult, ScalarValue,
};
use datafusion_expr::{
    logical_plan::{Filter, Limit, LogicalPlan},
    utils::conjunction,
    Expr,
};

#[derive(Debug, Default)]
pub(crate) struct NormalizeTableScanPushdown;

impl NormalizeTableScanPushdown {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl OptimizerRule for NormalizeTableScanPushdown {
    fn name(&self) -> &str {
        "normalize_table_scan_pushdown"
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
    let LogicalPlan::TableScan(mut scan) = plan else {
        return Ok(Transformed::no(plan));
    };

    if scan.filters.is_empty() && scan.fetch.is_none() {
        return Ok(Transformed::no(LogicalPlan::TableScan(scan)));
    }

    let filters = mem::take(&mut scan.filters);
    let fetch = scan.fetch.take();
    let mut plan = LogicalPlan::TableScan(scan);

    if let Some(filter_expr) = conjunction(filters) {
        let filter = Filter::try_new(filter_expr, Arc::new(plan))?;
        plan = LogicalPlan::Filter(filter);
    }

    if let Some(fetch) = fetch {
        let fetch_i64 = i64::try_from(fetch).map_err(|_| {
            DataFusionError::Execution(format!("fetch {fetch} does not fit into i64"))
        })?;
        let fetch_expr = Expr::Literal(ScalarValue::Int64(Some(fetch_i64)));
        let limit = Limit {
            skip: None,
            fetch: Some(Box::new(fetch_expr)),
            input: Arc::new(plan),
        };
        plan = LogicalPlan::Limit(limit);
    }

    Ok(Transformed::yes(plan))
}
