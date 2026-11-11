//! Rewrites an IN list that has a value other than a non-null literal:
//! `x IN (v1, .., vk)` as `x = v1 OR .. OR x = vk`, and `x NOT IN (v1, .., vk)`
//! as `x <> v1 AND .. AND x <> vk`. A list of literals stays, for the
//! membership gadget. `SimplifyExpressions` merges an OR of equalities on one
//! column back into an IN list, so this rule runs after its last pass.
//!
//! TODO(#183): a literal list costs a zerocheck of degree `k + 1`, whose
//! expansion grows with the number of data columns of `x`. Prove long lists
//! as a semi join (anti join for `NOT IN`) with the list as a public table.

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{
    Result,
    tree_node::{Transformed, TreeNode},
};
use datafusion_expr::{
    Expr, expr::InList, expr_rewriter::NamePreserver, lit, logical_plan::LogicalPlan,
};
use tt_core::irs::nodes::plan::exprs::in_list::literal_values;

#[derive(Debug, Default)]
pub(crate) struct InListAsComparisons;

impl InListAsComparisons {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl OptimizerRule for InListAsComparisons {
    fn name(&self) -> &str {
        "in_list_as_comparisons"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        Some(ApplyOrder::BottomUp)
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> Result<Transformed<LogicalPlan>> {
        plan.transform_up_with_subqueries(rewrite_plan)
    }
}

fn rewrite_plan(plan: LogicalPlan) -> Result<Transformed<LogicalPlan>> {
    let name_preserver = NamePreserver::new(&plan);
    plan.map_expressions(|expr| {
        let name = name_preserver.save(&expr);
        expr.transform_up(|expr| match expr {
            Expr::InList(in_list) if literal_values(&in_list).is_none() => {
                Ok(Transformed::yes(as_comparisons(in_list)))
            }
            other => Ok(Transformed::no(other)),
        })
        .map(|res| res.update_data(|expr| name.restore(expr)))
    })
}

fn as_comparisons(in_list: InList) -> Expr {
    let InList {
        expr,
        list,
        negated,
    } = in_list;
    list.into_iter()
        .map(|value| match negated {
            false => expr.as_ref().clone().eq(value),
            true => expr.as_ref().clone().not_eq(value),
        })
        .reduce(|acc, comparison| match negated {
            false => acc.or(comparison),
            true => acc.and(comparison),
        })
        .unwrap_or_else(|| lit(negated))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::{
        arrow::{
            array::{Int64Array, StringArray},
            datatypes::{DataType, Field, Schema},
            record_batch::RecordBatch,
            util::pretty::pretty_format_batches,
        },
        datasource::MemTable,
        optimizer::{Optimizer, OptimizerContext},
        prelude::DataFrame,
    };
    use datafusion_common::tree_node::{TreeNode, TreeNodeRecursion};
    use datafusion_expr::{Expr, LogicalPlan};

    use super::{InListAsComparisons, literal_values};
    use crate::{lp_analyzer::analyze_logical_plan, lp_optimizer::rules};

    /// Whether `plan` has an IN list of literals, and one with another value.
    fn in_lists(plan: &LogicalPlan) -> (bool, bool) {
        let mut found = (false, false);
        plan.apply(|plan| {
            for expr in plan.expressions() {
                expr.apply(|e| {
                    if let Expr::InList(in_list) = e {
                        match literal_values(in_list) {
                            Some(_) => found.0 = true,
                            None => found.1 = true,
                        }
                    }
                    Ok(TreeNodeRecursion::Continue)
                })?;
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
        found
    }

    /// Each query gives the same rows after the rule as with DataFusion
    /// evaluating it. A list with a column value is rewritten, by this rule and
    /// by the full rule set; a list of literals is kept by both.
    #[tokio::test]
    async fn rewritten_in_list_matches_datafusion() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("k", DataType::Int64, false),
            Field::new("j", DataType::Int64, false),
            Field::new("s", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from_iter_values(0..8)),
                Arc::new(Int64Array::from_iter_values([0, 5, 2, 7, 1, 5, 0, 3])),
                Arc::new(StringArray::from(vec![
                    "SM CASE", "SM BOX", "LG BOX", "SM PKG", "MED BAG", "SM PACK", "LG PKG", "SM",
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

        for (query, literal) in [
            ("SELECT k FROM t WHERE k IN (j, 5, 6, 7)", false),
            ("SELECT k FROM t WHERE k NOT IN (j + 1, 1, 3, 5)", false),
            (
                "SELECT k FROM t WHERE s IN ('SM CASE', 'SM BOX', 'SM PACK', 'SM PKG')",
                true,
            ),
            (
                "SELECT k FROM t WHERE s NOT IN ('SM CASE', 'SM BOX', 'SM PACK', 'SM PKG')",
                true,
            ),
            ("SELECT k, k + 1 IN (2, 4, 6, 8) AS even FROM t", true),
        ] {
            let expected = ctx.sql(query).await.unwrap().collect().await.unwrap();

            let plan = ctx.sql(query).await.unwrap().into_unoptimized_plan();
            let optimized = ctx.state().optimize(&plan).unwrap();
            assert_ne!(
                in_lists(&optimized),
                (false, false),
                "{query} has no IN list"
            );
            let rewritten = Optimizer::with_rules(vec![Arc::new(InListAsComparisons::new())])
                .optimize(optimized, &OptimizerContext::new(), |_, _| {})
                .unwrap();
            assert_eq!(
                in_lists(&rewritten),
                (literal, false),
                "{query}:\n{rewritten}"
            );
            let actual = DataFrame::new(ctx.state(), rewritten)
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

            let analyzed = analyze_logical_plan(plan, crate::lp_analyzer::rules());
            let planned = Optimizer::with_rules(rules(&ctx))
                .optimize(analyzed, &OptimizerContext::new(), |_, _| {})
                .unwrap();
            assert_eq!(in_lists(&planned), (literal, false), "{query}:\n{planned}");
        }
    }
}
