//! The SQL a proof covers. [`ensure_supported`] rejects a plan outside it with
//! an error before the IR is built; the node constructors assert the same
//! conditions, for trees built without it.

use datafusion_common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion_common::{DataFusionError, Result};
use datafusion_expr::{Expr, Join, JoinType, LogicalPlan};

pub fn ensure_supported(plan: &LogicalPlan) -> Result<()> {
    plan.apply_with_subqueries(|node| {
        if let LogicalPlan::Join(join) = node
            && !is_inner_equijoin(join)
        {
            return Err(DataFusionError::NotImplemented(unsupported_join(join)));
        }
        node.apply_expressions(|expr| {
            expr.apply(|expr| match expr {
                Expr::Literal(value) if value.is_null() => {
                    Err(DataFusionError::NotImplemented(NULL_LITERAL.to_string()))
                }
                Expr::Case(case) if case.else_expr.is_none() => Err(
                    DataFusionError::NotImplemented(CASE_WITHOUT_ELSE.to_string()),
                ),
                _ => Ok(TreeNodeRecursion::Continue),
            })
        })
    })
    .map(|_| ())
}

/// Both join protocols prove inner equijoins without a residual filter.
pub(crate) fn is_inner_equijoin(join: &Join) -> bool {
    join.join_type == JoinType::Inner && !join.on.is_empty() && join.filter.is_none()
}

pub(crate) fn unsupported_join(join: &Join) -> String {
    format!(
        "only inner equijoins without a join filter are supported, got {} join with {} keys{}",
        join.join_type,
        join.on.len(),
        if join.filter.is_some() {
            " and a filter"
        } else {
            ""
        },
    )
}

// The proof encodes NULL as 0, so it would treat a NULL as a 0.
pub(crate) const NULL_LITERAL: &str = "NULL is not supported: the query has a NULL literal";
pub(crate) const CASE_WITHOUT_ELSE: &str = "NULL is not supported: CASE without ELSE yields NULL";
