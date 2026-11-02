//! Rewrites `x LIKE p`, where `p` has no unescaped wildcard, as `x = s` for
//! the string `s` that `p` matches (`x <> s` for `NOT LIKE`). The LIKE gadget
//! proves `p` as a prefix, so it must not see such a pattern.
//! `SimplifyExpressions` makes the same rewrite only for a pattern without
//! any `\`, and keeps `'a\_b'` as a LIKE.

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{
    Result, ScalarValue,
    tree_node::{Transformed, TreeNode},
};
use datafusion_expr::{
    BinaryExpr, Expr, Operator, expr::Like, expr_rewriter::NamePreserver, logical_plan::LogicalPlan,
};
use tt_core::irs::nodes::utils::sweep_factors::like_pattern_literal;

#[derive(Debug, Default)]
pub(crate) struct LikeWithoutWildcardAsEquality;

impl LikeWithoutWildcardAsEquality {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl OptimizerRule for LikeWithoutWildcardAsEquality {
    fn name(&self) -> &str {
        "like_without_wildcard_as_equality"
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
            Expr::Like(like) => Ok(match as_equality(&like) {
                Some(equality) => Transformed::yes(equality),
                None => Transformed::no(Expr::Like(like)),
            }),
            other => Ok(Transformed::no(other)),
        })
        .map(|res| res.update_data(|expr| name.restore(expr)))
    })
}

fn as_equality(like: &Like) -> Option<Expr> {
    if like.case_insensitive || like.escape_char.is_some() {
        return None;
    }
    let literal = |pattern: &str| String::from_utf8(like_pattern_literal(pattern)?).ok();
    let right = match like.pattern.as_ref() {
        Expr::Literal(ScalarValue::Utf8(Some(p))) => ScalarValue::Utf8(Some(literal(p)?)),
        Expr::Literal(ScalarValue::LargeUtf8(Some(p))) => ScalarValue::LargeUtf8(Some(literal(p)?)),
        Expr::Literal(ScalarValue::Utf8View(Some(p))) => ScalarValue::Utf8View(Some(literal(p)?)),
        _ => return None,
    };
    Some(Expr::BinaryExpr(BinaryExpr::new(
        like.expr.clone(),
        if like.negated {
            Operator::NotEq
        } else {
            Operator::Eq
        },
        Box::new(Expr::Literal(right)),
    )))
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
    use datafusion_common::tree_node::TreeNode;
    use datafusion_expr::{Expr, LogicalPlan};

    use super::LikeWithoutWildcardAsEquality;
    use crate::{lp_analyzer::analyze_logical_plan, lp_optimizer::rules};

    fn has_like(plan: &LogicalPlan) -> bool {
        plan.exists(|plan| {
            plan.expressions().iter().try_fold(false, |found, expr| {
                Ok(found || expr.exists(|e| Ok(matches!(e, Expr::Like(_))))?)
            })
        })
        .unwrap()
    }

    /// Each query gives the same rows with its LIKE rewritten as with
    /// DataFusion evaluating it, and the full rule set leaves no LIKE.
    #[tokio::test]
    async fn rewritten_like_matches_datafusion() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("k", DataType::Int64, false),
            Field::new("s", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from_iter_values(0..6)),
                Arc::new(StringArray::from(vec![
                    "a_b", "axb", "a_bc", "a%", r"a\b", "a",
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
            r"SELECT k FROM t WHERE s LIKE 'a\_b'",
            r"SELECT k FROM t WHERE s NOT LIKE 'a\_b'",
            r"SELECT k FROM t WHERE s LIKE 'a\%'",
            r"SELECT k FROM t WHERE s LIKE 'a\\b'",
            r"SELECT k, s LIKE 'a\_bc' AS m FROM t",
        ] {
            let expected = ctx.sql(query).await.unwrap().collect().await.unwrap();

            let plan = ctx.sql(query).await.unwrap().into_unoptimized_plan();
            let optimized = ctx.state().optimize(&plan).unwrap();
            assert!(has_like(&optimized), "{query} has no LIKE to rewrite");
            let rewritten =
                Optimizer::with_rules(vec![Arc::new(LikeWithoutWildcardAsEquality::new())])
                    .optimize(optimized, &OptimizerContext::new(), |_, _| {})
                    .unwrap();
            assert!(!has_like(&rewritten), "{query} keeps a LIKE:\n{rewritten}");
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
            assert!(!has_like(&planned), "{query} keeps a LIKE:\n{planned}");
        }
    }

    /// A pattern with a wildcard stays a LIKE.
    #[tokio::test]
    async fn a_pattern_with_a_wildcard_stays() {
        let schema = Arc::new(Schema::new(vec![Field::new("s", DataType::Utf8, false)]));
        let ctx = tt_core::session::session_context();
        ctx.register_table(
            "t",
            Arc::new(MemTable::try_new(schema, vec![vec![]]).unwrap()),
        )
        .unwrap();
        let plan = ctx
            .sql(r"SELECT s FROM t WHERE s LIKE 'a\_b%'")
            .await
            .unwrap()
            .into_optimized_plan()
            .unwrap();
        let rewritten = Optimizer::with_rules(vec![Arc::new(LikeWithoutWildcardAsEquality::new())])
            .optimize(plan, &OptimizerContext::new(), |_, _| {})
            .unwrap();
        assert!(has_like(&rewritten), "{rewritten}");
    }
}
