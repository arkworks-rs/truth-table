use datafusion::optimizer::{
    ApplyOrder, OptimizerConfig, OptimizerRule, push_down_filter::PushDownFilter,
};
use datafusion_common::tree_node::Transformed;
use datafusion_expr::logical_plan::LogicalPlan;

/// DataFusion's `PushDownFilter` with the guard of apache/datafusion#21057
/// (released in 54.0.0): a filter stays above a node with a fetch or skip.
/// DataFusion 46 pushes a filter below a `Sort` with a fetch (a top-k), so
/// `Filter(Sort(fetch = k))` keeps the first k rows that pass the filter
/// instead of the rows among the first k that do.
#[derive(Debug, Default)]
pub struct FetchSafePushDownFilter {
    inner: PushDownFilter,
}

impl FetchSafePushDownFilter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl OptimizerRule for FetchSafePushDownFilter {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        self.inner.apply_order()
    }

    #[allow(deprecated)]
    fn supports_rewrite(&self) -> bool {
        self.inner.supports_rewrite()
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        config: &dyn OptimizerConfig,
    ) -> datafusion_common::Result<Transformed<LogicalPlan>> {
        if let LogicalPlan::Filter(filter) = &plan
            && has_fetch_or_skip(&filter.input)
        {
            return Ok(Transformed::no(plan));
        }
        self.inner.rewrite(plan, config)
    }
}

fn has_fetch_or_skip(plan: &LogicalPlan) -> bool {
    match plan {
        LogicalPlan::Limit(_) => true,
        LogicalPlan::Sort(sort) => sort.fetch.is_some(),
        LogicalPlan::TableScan(scan) => scan.fetch.is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::optimizer::{Optimizer, OptimizerContext, push_down_filter::PushDownFilter};
    use datafusion_expr::{LogicalPlan, col, lit, logical_plan::table_scan};

    use super::FetchSafePushDownFilter;

    /// `SELECT * FROM (SELECT * FROM t ORDER BY k LIMIT 3) WHERE v = 1`, with
    /// the LIMIT already folded into the Sort as `PushDownLimit` does.
    fn filter_over_top_k() -> LogicalPlan {
        let schema = Schema::new(vec![
            Field::new("k", DataType::Int64, false),
            Field::new("v", DataType::Int64, false),
        ]);
        let sort = table_scan(Some("t"), &schema, None)
            .unwrap()
            .sort_with_limit(vec![col("k").sort(true, false)], Some(3))
            .unwrap()
            .build()
            .unwrap();
        datafusion_expr::LogicalPlanBuilder::from(sort)
            .filter(col("v").eq(lit(1i64)))
            .unwrap()
            .build()
            .unwrap()
    }

    fn top_is_filter(
        rule: impl datafusion::optimizer::OptimizerRule + Send + Sync + 'static,
    ) -> bool {
        let optimized = Optimizer::with_rules(vec![std::sync::Arc::new(rule)])
            .optimize(filter_over_top_k(), &OptimizerContext::new(), |_, _| {})
            .unwrap();
        matches!(optimized, LogicalPlan::Filter(_))
    }

    #[test]
    fn datafusion_46_pushes_a_filter_below_a_top_k() {
        assert!(!top_is_filter(PushDownFilter::new()));
    }

    #[test]
    fn a_filter_stays_above_a_top_k() {
        assert!(top_is_filter(FetchSafePushDownFilter::new()));
    }
}
