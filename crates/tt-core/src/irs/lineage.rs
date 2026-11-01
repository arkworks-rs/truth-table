//! Which base-table column a plan's output column copies. The walk follows
//! only operators that pass a column's values through unchanged, so a column
//! with a lineage holds values of its base column.

use std::collections::BTreeSet;

use datafusion::arrow::datatypes::Field;
use datafusion_common::{Column, DFSchema};
use datafusion_expr::{Expr, ExprSchemable, JoinType, LogicalPlan};

use crate::irs::nodes::plan::{
    compaction::CompactionLogicalNode, result_check::ResultCheckLogicalNode,
};

pub struct BaseColumn<'a> {
    pub table: String,
    pub column: String,
    /// The unfiltered, unlimited table scan the column is read from.
    pub scan: &'a LogicalPlan,
}

/// The base column that output column `index` of `plan` copies, if any.
pub fn base_column(plan: &LogicalPlan, index: usize) -> Option<BaseColumn<'_>> {
    match plan {
        LogicalPlan::Projection(projection) => {
            let column = copied_column(projection.expr.get(index)?, projection.input.schema())?;
            let index = projection.input.schema().index_of_column(&column).ok()?;
            base_column(&projection.input, index)
        }
        LogicalPlan::Aggregate(aggregate) => {
            let column = copied_column(aggregate.group_expr.get(index)?, aggregate.input.schema())?;
            let index = aggregate.input.schema().index_of_column(&column).ok()?;
            base_column(&aggregate.input, index)
        }
        LogicalPlan::Join(join) if join.join_type == JoinType::Inner => {
            let left_len = join.left.schema().fields().len();
            if index < left_len {
                base_column(&join.left, index)
            } else {
                base_column(&join.right, index - left_len)
            }
        }
        LogicalPlan::SubqueryAlias(alias) => base_column(&alias.input, index),
        LogicalPlan::Filter(filter) => base_column(&filter.input, index),
        LogicalPlan::Limit(limit) => base_column(&limit.input, index),
        LogicalPlan::Sort(sort) => base_column(&sort.input, index),
        LogicalPlan::Extension(extension) => {
            let node = extension.node.as_any();
            let input = if let Some(compaction) = node.downcast_ref::<CompactionLogicalNode>() {
                compaction.input()
            } else {
                node.downcast_ref::<ResultCheckLogicalNode>()?.input()
            };
            base_column(input, index)
        }
        LogicalPlan::TableScan(scan) => {
            if !scan.filters.is_empty() || scan.fetch.is_some() {
                return None;
            }
            let field = scan.projected_schema.fields().get(index)?;
            Some(BaseColumn {
                table: scan.table_name.table().to_string(),
                column: field.name().clone(),
                scan: plan,
            })
        }
        _ => None,
    }
}

/// An output column that carries the rank of its base column.
pub struct RankedOutput {
    name: String,
    /// The base column, as `(table, column)`.
    pub base: (String, String),
}

/// The output columns of `plan` whose base column is in `ranked`: the
/// columns that carry a rank segment. Prover and verifier derive them from
/// the same plan.
pub fn ranked_outputs(
    plan: &LogicalPlan,
    ranked: &BTreeSet<(String, String)>,
) -> Vec<RankedOutput> {
    if ranked.is_empty() {
        return Vec::new();
    }
    (0..plan.schema().fields().len())
        .filter_map(|index| {
            let base = ranked_base(plan, index, ranked)?;
            Some(RankedOutput {
                name: plan.schema().field(index).name().clone(),
                base,
            })
        })
        .collect()
}

/// The ranked output that `field`, a column of the node's payload, is. It is
/// matched by name: a verifier's payload does not always know a field's
/// qualifier. Planning refuses a plan where the name is ambiguous
/// ([`ambiguous_rank`]).
pub fn ranked_output<'a>(outputs: &'a [RankedOutput], field: &Field) -> Option<&'a RankedOutput> {
    outputs.iter().find(|output| output.name == *field.name())
}

/// A column name of `plan`'s output that two string columns share while
/// they do not carry the same rank, if any. Payload fields are matched to
/// ranked outputs by name, so such a name would get one rank for both.
pub fn ambiguous_rank(plan: &LogicalPlan, ranked: &BTreeSet<(String, String)>) -> Option<String> {
    let mut seen: Vec<(&String, Option<(String, String)>)> = Vec::new();
    for (index, field) in plan.schema().fields().iter().enumerate() {
        if !is_string_type(field.data_type()) {
            continue;
        }
        let base = ranked_base(plan, index, ranked);
        match seen.iter().find(|(name, _)| *name == field.name()) {
            Some((_, other)) if *other != base => return Some(field.name().clone()),
            Some(_) => {}
            None => seen.push((field.name(), base)),
        }
    }
    None
}

fn ranked_base(
    plan: &LogicalPlan,
    index: usize,
    ranked: &BTreeSet<(String, String)>,
) -> Option<(String, String)> {
    let base = base_column(plan, index)?;
    let base = (base.table, base.column);
    ranked.contains(&base).then_some(base)
}

/// The input column `expr` copies: a column, under aliases and casts that
/// keep a string a string.
fn copied_column(expr: &Expr, schema: &DFSchema) -> Option<Column> {
    match expr {
        Expr::Column(column) => Some(column.clone()),
        Expr::Alias(alias) => copied_column(&alias.expr, schema),
        Expr::Cast(cast) if is_string_cast(&cast.expr, &cast.data_type, schema) => {
            copied_column(&cast.expr, schema)
        }
        Expr::TryCast(cast) if is_string_cast(&cast.expr, &cast.data_type, schema) => {
            copied_column(&cast.expr, schema)
        }
        _ => None,
    }
}

fn is_string_cast(
    expr: &Expr,
    target: &datafusion::arrow::datatypes::DataType,
    schema: &DFSchema,
) -> bool {
    is_string_type(target)
        && expr
            .get_type(schema)
            .is_ok_and(|from| is_string_type(&from))
}

pub(crate) fn is_string_type(data_type: &datafusion::arrow::datatypes::DataType) -> bool {
    use datafusion::arrow::datatypes::DataType;
    matches!(
        data_type,
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View
    )
}
