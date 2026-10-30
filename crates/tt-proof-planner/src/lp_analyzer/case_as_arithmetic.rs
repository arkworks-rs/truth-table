//! Rewrites a `CASE` with integer or decimal results as arithmetic over its
//! conditions:
//!
//! ```text
//! CASE WHEN p1 THEN x1 WHEN p2 THEN x2 ELSE y END
//!   = c1 * x1 + (1 - c1) * (c2 * x2 + (1 - c2) * y),   ci = CAST(pi AS INT)
//! ```
//!
//! Each `ci` is 0 or 1, and `1 - ci` lets a later branch count only where no
//! earlier one held. `+`, `-`, `*` and these casts are proved, so `CASE`
//! needs no check of its own. The rewrite runs after type coercion: the
//! branches already share the `CASE`'s type, and a decimal factor `ci` keeps
//! scale 0, which leaves the product at the branch's scale. Operand
//! alignment would rescale it, so the rule also runs after that.

use super::common::cast_expression_to_type;
use datafusion::{
    arrow::datatypes::DataType, config::ConfigOptions, optimizer::analyzer::AnalyzerRule,
};
use datafusion_common::{
    DFSchema, Result, ScalarValue,
    tree_node::{Transformed, TreeNode},
};
use datafusion_expr::{
    Expr, ExprSchemable, cast, expr::Case, expr_rewriter::NamePreserver, logical_plan::LogicalPlan,
    utils::merge_schema,
};

#[derive(Debug, Default)]
pub(crate) struct CaseAsArithmetic;

impl CaseAsArithmetic {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl AnalyzerRule for CaseAsArithmetic {
    fn name(&self) -> &str {
        "case_as_arithmetic"
    }

    fn analyze(&self, plan: LogicalPlan, _config: &ConfigOptions) -> Result<LogicalPlan> {
        plan.transform_up_with_subqueries(rewrite_plan)
            .map(|res| res.data)
    }
}

fn rewrite_plan(plan: LogicalPlan) -> Result<Transformed<LogicalPlan>> {
    let schema = merge_schema(&plan.inputs());
    let name_preserver = NamePreserver::new(&plan);
    plan.map_expressions(|expr| {
        let name = name_preserver.save(&expr);
        expr.transform_up(|expr| match expr {
            Expr::Case(case) => rewrite_case(case, &schema),
            other => Ok(Transformed::no(other)),
        })
        .map(|res| res.update_data(|expr| name.restore(expr)))
    })
}

/// A `CASE` without `ELSE` or with other results is left as it is, and
/// planning refuses it.
fn rewrite_case(case: Case, schema: &DFSchema) -> Result<Transformed<Expr>> {
    let case_type = Expr::Case(case.clone()).get_type(schema)?;
    let factor_type = match &case_type {
        DataType::Decimal128(..) => DataType::Decimal128(20, 0),
        other if other.is_integer() => other.clone(),
        _ => return Ok(Transformed::no(Expr::Case(case))),
    };
    let Some(else_expr) = case.else_expr else {
        return Ok(Transformed::no(Expr::Case(case)));
    };

    let one = Expr::Literal(ScalarValue::Int64(Some(1)).cast_to(&factor_type)?);
    let mut value = *else_expr;
    for (when, then) in case.when_then_expr.into_iter().rev() {
        let condition = match &case.expr {
            Some(base) => base.as_ref().clone().eq(*when),
            None => *when,
        };
        // Arrow casts a boolean to an integer, not to a decimal.
        let factor = match &factor_type {
            DataType::Decimal128(..) => cast(cast(condition, DataType::Int64), factor_type.clone()),
            _ => cast(condition, factor_type.clone()),
        };
        value = factor.clone() * *then + (one.clone() - factor) * value;
    }
    cast_expression_to_type(value, &case_type, schema).map(Transformed::yes)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::{
        arrow::{
            array::{BooleanArray, Decimal128Array, Int64Array},
            datatypes::{DataType, Field, Schema},
            record_batch::RecordBatch,
            util::pretty::pretty_format_batches,
        },
        datasource::MemTable,
        prelude::DataFrame,
    };
    use datafusion_common::tree_node::TreeNode;
    use datafusion_expr::Expr;

    use crate::lp_analyzer::{analyze_logical_plan, rules};

    /// Each query gives the same rows and types with its `CASE`s rewritten
    /// as with DataFusion evaluating them.
    #[tokio::test]
    async fn rewritten_case_matches_datafusion() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("k", DataType::Int64, false),
            Field::new("d", DataType::Decimal128(15, 2), false),
            Field::new("b", DataType::Boolean, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from_iter_values(0..8)),
                Arc::new(
                    Decimal128Array::from_iter_values([105, -250, 3999, 0, 712, 18, 50000, 1])
                        .with_precision_and_scale(15, 2)
                        .unwrap(),
                ),
                Arc::new(BooleanArray::from(vec![
                    true, false, true, true, false, false, true, false,
                ])),
            ],
        )
        .unwrap();
        let ctx = tt_core::session::session_context();
        ctx.register_table(
            "t",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();

        for query in [
            // A later condition that also holds does not count.
            "SELECT k, CASE WHEN k < 3 THEN d WHEN k < 6 THEN d * 2 ELSE 0 END AS v FROM t",
            "SELECT SUM(CASE WHEN b THEN d ELSE 0 END) FROM t",
            "SELECT k, CASE k WHEN 1 THEN 10 WHEN 2 THEN 20 ELSE 30 END FROM t",
            "SELECT k, CASE WHEN k < 4 THEN CASE WHEN b THEN 1 ELSE 2 END ELSE 3 END FROM t",
            "SELECT k FROM t WHERE CASE WHEN b THEN k ELSE 0 END > 2",
            "SELECT b, SUM(CASE WHEN k < 5 THEN d * d ELSE d END) FROM t GROUP BY b ORDER BY b",
        ] {
            let expected = ctx.sql(query).await.unwrap().collect().await.unwrap();

            let plan = ctx.sql(query).await.unwrap().into_unoptimized_plan();
            let analyzed = analyze_logical_plan(plan, rules());
            let has_case = analyzed
                .exists(|plan| {
                    plan.expressions().iter().try_fold(false, |found, expr| {
                        Ok(found || expr.exists(|e| Ok(matches!(e, Expr::Case(_))))?)
                    })
                })
                .unwrap();
            assert!(!has_case, "{query} keeps a CASE:\n{analyzed}");
            let actual = DataFrame::new(ctx.state(), analyzed)
                .collect()
                .await
                .unwrap();

            assert_eq!(
                expected[0].schema().fields(),
                actual[0].schema().fields(),
                "{query}"
            );
            assert_eq!(
                pretty_format_batches(&expected).unwrap().to_string(),
                pretty_format_batches(&actual).unwrap().to_string(),
                "{query}"
            );
        }
    }
}
