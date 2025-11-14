use datafusion::{
    arrow::datatypes::DataType, config::ConfigOptions, optimizer::analyzer::AnalyzerRule,
};
use datafusion_common::{tree_node::Transformed, DFSchema, Result};
use datafusion_expr::{expr::AggregateFunction as AggregateExpr, logical_plan::LogicalPlan, Expr};

use super::common::cast_expression_to_type;

#[derive(Debug, Default)]
pub(crate) struct AlignAggInputToOutput;

impl AlignAggInputToOutput {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl AnalyzerRule for AlignAggInputToOutput {
    fn name(&self) -> &str {
        "align_agg_input_to_output"
    }

    fn analyze(&self, plan: LogicalPlan, _config: &ConfigOptions) -> Result<LogicalPlan> {
        plan.transform_up_with_subqueries(align_plan_node)
            .map(|res| res.data)
    }
}

fn align_plan_node(plan: LogicalPlan) -> Result<Transformed<LogicalPlan>> {
    match plan {
        LogicalPlan::Aggregate(mut aggregate) => {
            let aggr_count = aggregate.aggr_expr.len();
            let schema_field_count = aggregate.schema.fields().len();
            if aggr_count == 0 || schema_field_count < aggr_count {
                return Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)));
            }

            let group_field_count = schema_field_count - aggr_count;
            let input_schema = aggregate.input.schema().clone();

            let mut changed = false;
            let mut new_aggr_expr = Vec::with_capacity(aggr_count);

            for (position, expr) in aggregate.aggr_expr.into_iter().enumerate() {
                let target_type = aggregate
                    .schema
                    .field(group_field_count + position)
                    .data_type()
                    .clone();
                let (aligned_expr, expr_changed) =
                    align_aggregate_expr(expr, target_type, input_schema.as_ref())?;
                changed |= expr_changed;
                new_aggr_expr.push(aligned_expr);
            }

            aggregate.aggr_expr = new_aggr_expr;

            if changed {
                Ok(Transformed::yes(LogicalPlan::Aggregate(aggregate)))
            } else {
                Ok(Transformed::no(LogicalPlan::Aggregate(aggregate)))
            }
        }
        other => Ok(Transformed::no(other)),
    }
}

fn align_aggregate_expr(
    expr: Expr,
    target_type: DataType,
    input_schema: &DFSchema,
) -> Result<(Expr, bool)> {
    match expr {
        Expr::AggregateFunction(mut agg) => {
            if !should_rewrite(&agg) {
                return Ok((Expr::AggregateFunction(agg), false));
            }

            let Some(first_arg) = agg.params.args.get_mut(0) else {
                return Ok((Expr::AggregateFunction(agg), false));
            };

            let rewritten = cast_expression_to_type(first_arg.clone(), &target_type, input_schema)?;
            let changed = rewritten != *first_arg;
            if changed {
                *first_arg = rewritten;
            }

            Ok((Expr::AggregateFunction(agg), changed))
        }
        other => Ok((other, false)),
    }
}

fn should_rewrite(agg: &AggregateExpr) -> bool {
    let name = agg.func.name();
    name.eq_ignore_ascii_case("sum") || name.eq_ignore_ascii_case("avg")
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_common::Result;
    use datafusion_expr::{
        expr::Cast, expr_fn::col, logical_plan::builder::table_scan, Expr, LogicalPlan,
    };
    use datafusion_functions_aggregate::expr_fn::{avg, count, sum};

    use crate::logical_plan_analyzer::{analyze_logical_plan, logical_plan_analyzer_rules};

    fn expect_aggregate(plan: &LogicalPlan) -> &datafusion_expr::logical_plan::Aggregate {
        match plan {
            LogicalPlan::Aggregate(agg) => agg,
            other => panic!("expected aggregate, found {other:?}"),
        }
    }

    #[test]
    fn casts_sum_input_to_output_type() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Decimal128(10, 2), false)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .aggregate(Vec::<Expr>::new(), vec![sum(col("a"))])?
            .build()?;

        let analyzed = analyze_logical_plan(plan, logical_plan_analyzer_rules());
        let agg = expect_aggregate(&analyzed);

        let target_type = agg.schema.field(0).data_type().clone();
        let Expr::AggregateFunction(aggregate_expr) =
            agg.aggr_expr.first().expect("agg expr").clone()
        else {
            panic!("expected aggregate function");
        };

        match aggregate_expr.params.args.first() {
            Some(Expr::Cast(Cast { data_type, expr })) => {
                assert_eq!(data_type, &target_type);
                assert!(!matches!(expr.as_ref(), Expr::Cast(_)));
            }
            other => panic!("expected casted argument, found {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn casts_avg_input_to_float() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, true)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .aggregate(Vec::<Expr>::new(), vec![avg(col("a"))])?
            .build()?;

        let analyzed = analyze_logical_plan(plan, logical_plan_analyzer_rules());
        let agg = expect_aggregate(&analyzed);
        let target_type = agg.schema.field(0).data_type().clone();

        assert_eq!(target_type, DataType::Float64);

        let Expr::AggregateFunction(aggregate_expr) =
            agg.aggr_expr.first().expect("agg expr").clone()
        else {
            panic!("expected aggregate function");
        };

        match aggregate_expr.params.args.first() {
            Some(Expr::Cast(Cast { data_type, .. })) => {
                assert_eq!(data_type, &DataType::Float64);
            }
            other => panic!("expected casted argument, found {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn skips_count() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Decimal128(8, 3), true)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .aggregate(Vec::<Expr>::new(), vec![count(col("a"))])?
            .build()?;

        let analyzed = analyze_logical_plan(plan, logical_plan_analyzer_rules());
        let agg = expect_aggregate(&analyzed);

        let Expr::AggregateFunction(aggregate_expr) =
            agg.aggr_expr.first().expect("agg expr").clone()
        else {
            panic!("expected aggregate function");
        };

        match aggregate_expr.params.args.first() {
            Some(Expr::Column(_)) => {}
            other => panic!("expected original argument, found {other:?}"),
        }

        Ok(())
    }
}
