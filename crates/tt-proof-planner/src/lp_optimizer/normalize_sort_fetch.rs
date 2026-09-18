use std::sync::Arc;

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{DataFusionError, Result as DataFusionResult, tree_node::Transformed};
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_common::DFSchema;
    use datafusion_expr::{LogicalPlan, Sort, col, logical_plan::EmptyRelation};

    use super::normalize_plan_node;

    #[test]
    fn top_k_sort_becomes_limit_over_full_sort() {
        let schema = Arc::new(
            DFSchema::try_from(Schema::new(vec![Field::new("key", DataType::Int64, false)]))
                .unwrap(),
        );
        let input = LogicalPlan::EmptyRelation(EmptyRelation {
            produce_one_row: false,
            schema,
        });
        let top_k = LogicalPlan::Sort(Sort {
            expr: vec![col("key").sort(true, false)],
            input: Arc::new(input.clone()),
            fetch: Some(3),
        });

        let rewritten = normalize_plan_node(top_k).unwrap().data;
        let LogicalPlan::Limit(limit) = rewritten else {
            panic!("top-k sort must produce an explicit LIMIT");
        };
        assert!(matches!(
            limit.get_skip_type().unwrap(),
            datafusion_expr::SkipType::Literal(0)
        ));
        assert!(matches!(
            limit.get_fetch_type().unwrap(),
            datafusion_expr::FetchType::Literal(Some(3))
        ));
        let LogicalPlan::Sort(sort) = limit.input.as_ref() else {
            panic!("LIMIT must retain a full-sort child");
        };
        assert_eq!(sort.fetch, None);
        assert_eq!(sort.input.as_ref(), &input);
    }
}
