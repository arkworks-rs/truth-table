use std::sync::Arc;

use datafusion::{config::ConfigOptions, optimizer::analyzer::AnalyzerRule};
use datafusion_common::{Result, tree_node::Transformed};
use datafusion_expr::{
    AggregateUDF, Expr,
    expr::{AggregateFunction as AggregateExpr, AggregateFunctionParams},
    logical_plan::{Aggregate, LogicalPlan},
};
use datafusion_functions_aggregate::{count::count_udaf, sum::sum_udaf};

#[derive(Debug, Default)]
pub(crate) struct AddAvgSupport;

impl AddAvgSupport {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl AnalyzerRule for AddAvgSupport {
    fn name(&self) -> &str {
        "add_avg_support"
    }

    fn analyze(&self, plan: LogicalPlan, _config: &ConfigOptions) -> Result<LogicalPlan> {
        plan.transform_up_with_subqueries(add_avg_support)
            .map(|res| res.data)
    }
}

fn add_avg_support(plan: LogicalPlan) -> Result<Transformed<LogicalPlan>> {
    match plan {
        LogicalPlan::Aggregate(mut aggregate) => {
            let mut changed = false;
            let aggr_expr = std::mem::take(&mut aggregate.aggr_expr);
            let mut existing = aggr_expr.clone();
            let mut new_aggr_expr = Vec::with_capacity(aggregate.aggr_expr.len() + 2);

            for expr in aggr_expr.into_iter() {
                let avg_params = match &expr {
                    Expr::AggregateFunction(agg) if is_avg(agg) => Some(agg.params.clone()),
                    _ => None,
                };

                new_aggr_expr.push(expr);

                if let Some(params) = avg_params {
                    let sum_expr = build_aggregate_expr(sum_udaf(), &params);
                    if !existing.contains(&sum_expr) {
                        existing.push(sum_expr.clone());
                        new_aggr_expr.push(sum_expr);
                        changed = true;
                    }

                    let count_expr = build_aggregate_expr(count_udaf(), &params);
                    if !existing.contains(&count_expr) {
                        existing.push(count_expr.clone());
                        new_aggr_expr.push(count_expr);
                        changed = true;
                    }
                }
            }

            if changed {
                let new_aggregate = Aggregate::try_new(
                    aggregate.input.clone(),
                    aggregate.group_expr.clone(),
                    new_aggr_expr,
                )?;
                Ok(Transformed::yes(LogicalPlan::Aggregate(new_aggregate)))
            } else {
                aggregate.aggr_expr = new_aggr_expr;
                Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)))
            }
        }
        other => Ok(Transformed::no(other)),
    }
}

fn is_avg(agg: &AggregateExpr) -> bool {
    agg.func.name().eq_ignore_ascii_case("avg")
}

fn build_aggregate_expr(udf: Arc<AggregateUDF>, params: &AggregateFunctionParams) -> Expr {
    Expr::AggregateFunction(AggregateExpr::new_udf(
        udf,
        params.args.clone(),
        params.distinct,
        params.filter.clone(),
        params.order_by.clone(),
        params.null_treatment,
    ))
}

#[cfg(test)]
mod tests {}
