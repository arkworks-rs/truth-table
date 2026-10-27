//! The SQL a proof covers. [`ensure_supported`] rejects a plan outside it with
//! an error before the IR is built; the node constructors assert the same
//! conditions, for trees built without it.

use datafusion_common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion_common::{DFSchema, DataFusionError, Result};
use datafusion_expr::{
    BinaryExpr, Expr, ExprSchemable, Join, JoinType, LogicalPlan, Operator, Sort,
    expr::{AggregateFunction, ScalarFunction},
};

use crate::irs::lineage::{base_column, is_string_type};
use crate::irs::nodes::{
    plan::compaction::CompactionLogicalNode, utils::contig_sort::difference_sign_type,
};
use crate::irs::string_order::{StringOrder, string_order};

pub fn ensure_supported(plan: &LogicalPlan) -> Result<()> {
    // Checked first: a compaction under an ORDER BY also cuts its keys' paths.
    if string_order() == StringOrder::Lexicographic {
        plan.apply_with_subqueries(|node| match node {
            LogicalPlan::Extension(extension)
                if extension.node.as_any().is::<CompactionLogicalNode>() =>
            {
                Err(DataFusionError::NotImplemented(
                    LEXICOGRAPHIC_COMPACTION.to_string(),
                ))
            }
            _ => Ok(TreeNodeRecursion::Continue),
        })?;
    }
    plan.apply_with_subqueries(|node| {
        if let LogicalPlan::Join(join) = node
            && !is_inner_equijoin(join)
        {
            return Err(DataFusionError::NotImplemented(unsupported_join(join)));
        }
        if let LogicalPlan::Sort(sort) = node {
            for index in 0..sort.expr.len() {
                sort_key_position(sort, index).map_err(DataFusionError::NotImplemented)?;
            }
        }
        let mut input_schema = DFSchema::empty();
        for input in node.inputs() {
            input_schema.merge(input.schema());
        }
        node.apply_expressions(|expr| {
            expr.apply(|expr| match expr {
                Expr::Literal(value) if value.is_null() => {
                    Err(DataFusionError::NotImplemented(NULL_LITERAL.to_string()))
                }
                Expr::Case(case) if case.else_expr.is_none() => Err(
                    DataFusionError::NotImplemented(CASE_WITHOUT_ELSE.to_string()),
                ),
                Expr::BinaryExpr(BinaryExpr { left, op, right })
                    if matches!(
                        op,
                        Operator::Lt | Operator::LtEq | Operator::Gt | Operator::GtEq
                    ) && [left, right]
                        .iter()
                        .any(|side| is_string_expr(side, &input_schema)) =>
                {
                    Err(DataFusionError::NotImplemented(format!(
                        "{STRING_COMPARISON}: {expr}"
                    )))
                }
                Expr::AggregateFunction(AggregateFunction { func, params })
                    if ["min", "max"].contains(&func.name().to_lowercase().as_str())
                        && params
                            .args
                            .iter()
                            .any(|arg| is_string_expr(arg, &input_schema)) =>
                {
                    Err(DataFusionError::NotImplemented(format!(
                        "{STRING_EXTREMUM}: {expr}"
                    )))
                }
                Expr::ScalarFunction(ScalarFunction { func, args })
                    if ["greatest", "least"].contains(&func.name().to_lowercase().as_str())
                        && args.iter().any(|arg| is_string_expr(arg, &input_schema)) =>
                {
                    Err(DataFusionError::NotImplemented(format!(
                        "{STRING_GREATEST_LEAST}: {expr}"
                    )))
                }
                _ => Ok(TreeNodeRecursion::Continue),
            })
        })
    })
    .map(|_| ())
}

fn is_string_expr(expr: &Expr, schema: &DFSchema) -> bool {
    expr.get_type(schema)
        .is_ok_and(|data_type| is_string_type(&data_type))
}

/// The position in the sort's input of ORDER BY key `index`, or why the
/// key cannot be proved. A string key is proved on its base column's rank
/// (TruthTable++ Rank-Based String Sort Check, §7.3, PIOP 13), so it must
/// copy a base column; in the lexicographic string order it is proved on
/// its characters (String Sort Check, §7.2, PIOP 11), which it must carry
/// from its table scan. Any other key must have an order-preserving
/// encoding.
pub(crate) fn sort_key_position(sort: &Sort, index: usize) -> std::result::Result<usize, String> {
    let key = &sort.expr[index].expr;
    let position = match key {
        Expr::Column(column) => sort.input.schema().index_of_column(column).ok(),
        _ => None,
    }
    .ok_or_else(|| format!("ORDER BY {key}: {SORT_KEY_NOT_A_COLUMN}"))?;
    let data_type = sort.input.schema().field(position).data_type();
    if is_string_type(data_type) {
        match string_order() {
            StringOrder::Rank if base_column(&sort.input, position).is_none() => {
                return Err(format!("ORDER BY {key}: {STRING_KEY_WITHOUT_LINEAGE}"));
            }
            StringOrder::Lexicographic if !carries_scan_characters(&sort.input, position) => {
                return Err(format!("ORDER BY {key}: {LEXICOGRAPHIC_KEY_PATH}"));
            }
            _ => {}
        }
    } else if difference_sign_type(data_type).is_none() {
        return Err(format!(
            "ORDER BY {key}: {UNORDERED_SORT_KEY} (type {data_type})"
        ));
    }
    Ok(position)
}

/// Whether output column `index` of `plan` is read from a table scan through
/// filters, column projections and subquery aliases only: the operators that
/// keep the scan's rows at their positions, so the scan's character table
/// still indexes them, and pass its character columns on.
fn carries_scan_characters(plan: &LogicalPlan, index: usize) -> bool {
    match plan {
        LogicalPlan::Projection(projection) => {
            let mut expr = projection.expr.get(index);
            while let Some(Expr::Alias(alias)) = expr {
                expr = Some(alias.expr.as_ref());
            }
            let Some(Expr::Column(column)) = expr else {
                return false;
            };
            projection
                .input
                .schema()
                .index_of_column(column)
                .is_ok_and(|index| carries_scan_characters(&projection.input, index))
        }
        LogicalPlan::SubqueryAlias(alias) => carries_scan_characters(&alias.input, index),
        LogicalPlan::Filter(filter) => carries_scan_characters(&filter.input, index),
        LogicalPlan::TableScan(scan) => {
            scan.filters.is_empty()
                && scan.fetch.is_none()
                && index < scan.projected_schema.fields().len()
        }
        _ => false,
    }
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

pub(crate) const SORT_KEY_NOT_A_COLUMN: &str =
    "an ORDER BY key must be a column of the sorted input";
pub(crate) const STRING_KEY_WITHOUT_LINEAGE: &str = "a string ORDER BY key must be a copy of a base-table column (through projections, aliases, filters, joins and GROUP BY keys), whose committed rank orders it";
pub(crate) const LEXICOGRAPHIC_KEY_PATH: &str = "in the lexicographic string order, a string ORDER BY key must be read from its table scan through filters, column projections and subquery aliases only, which keep its characters";
pub(crate) const LEXICOGRAPHIC_COMPACTION: &str = "the lexicographic string order does not support compaction: a compaction's character columns are bound for a single LIKE column only";
pub(crate) const UNORDERED_SORT_KEY: &str = "an ORDER BY key needs an order-preserving encoding";
// These would need the TruthTable++ Lexicographic Sortedness Check (§7.2,
// PIOP 10); a string's hash does not preserve its order.
pub(crate) const STRING_COMPARISON: &str = "comparing strings with <, <=, > or >= is not supported";
pub(crate) const STRING_EXTREMUM: &str = "MIN and MAX over strings are not supported";
pub(crate) const STRING_GREATEST_LEAST: &str = "GREATEST and LEAST over strings are not supported";
