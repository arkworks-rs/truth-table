use std::collections::HashSet;

use crate::irs::nodes::hints::column_constraint_metadata;
use datafusion_common::{Column, DFSchemaRef, TableReference};
use datafusion_expr::{Expr, Join};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinMode {
    ONE_TO_MANY,
    MANY_TO_ONE,
    ONE_TO_ONE,
    MANY_TO_MANY,
}

/// Decide join mode directly from the logical join specification.
///
/// This keeps the plan-side materialization decision and gadget-side optimization
/// decision sourced from the same place, so they cannot drift.
pub fn decide_join_mode(join: &Join) -> JoinMode {
    if join.on.is_empty() {
        return JoinMode::MANY_TO_MANY;
    }

    let left_schema = join.left.schema();
    let right_schema = join.right.schema();
    let left_tables = collect_tables_from_schema(left_schema);
    let right_tables = collect_tables_from_schema(right_schema);

    let mut left_is_pk = true;
    let mut right_is_pk = true;
    let mut left_is_fk_to_right = true;
    let mut right_is_fk_to_left = true;

    for (left_expr, right_expr) in &join.on {
        let Some(left_col) = expr_to_column(left_expr) else {
            return JoinMode::MANY_TO_MANY;
        };
        let Some(right_col) = expr_to_column(right_expr) else {
            return JoinMode::MANY_TO_MANY;
        };

        let left_table = table_name_from_column(&left_col)
            .or_else(|| infer_table_from_schema(left_schema, left_col.name.as_str()))
            .or_else(|| single_table_name(&left_tables));
        let right_table = table_name_from_column(&right_col)
            .or_else(|| infer_table_from_schema(right_schema, right_col.name.as_str()))
            .or_else(|| single_table_name(&right_tables));

        let left_meta = left_table
            .as_deref()
            .and_then(|tbl| column_constraint_metadata(tbl, left_col.name.as_str()));
        let right_meta = right_table
            .as_deref()
            .and_then(|tbl| column_constraint_metadata(tbl, right_col.name.as_str()));

        let left_pk = left_meta.as_ref().map(|m| m.is_pk).unwrap_or(false);
        let right_pk = right_meta.as_ref().map(|m| m.is_pk).unwrap_or(false);
        left_is_pk &= left_pk;
        right_is_pk &= right_pk;

        let left_fk_to_right = left_meta
            .as_ref()
            .and_then(|m| m.fk_ref_table.as_ref().map(|t| (t, &m.fk_ref_columns)))
            .map(|(ref_table, ref_cols)| {
                right_table
                    .as_deref()
                    .map(|t| table_name_from_qualifier(ref_table) == t)
                    .unwrap_or(true)
                    && ref_cols
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(right_col.name.as_str()))
            })
            .unwrap_or(false);
        let right_fk_to_left = right_meta
            .as_ref()
            .and_then(|m| m.fk_ref_table.as_ref().map(|t| (t, &m.fk_ref_columns)))
            .map(|(ref_table, ref_cols)| {
                left_table
                    .as_deref()
                    .map(|t| table_name_from_qualifier(ref_table) == t)
                    .unwrap_or(true)
                    && ref_cols
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(left_col.name.as_str()))
            })
            .unwrap_or(false);

        left_is_fk_to_right &= left_fk_to_right;
        right_is_fk_to_left &= right_fk_to_left;
    }

    if left_is_pk && right_is_fk_to_left {
        JoinMode::ONE_TO_MANY
    } else if right_is_pk && left_is_fk_to_right {
        JoinMode::MANY_TO_ONE
    } else if left_is_pk && right_is_pk {
        JoinMode::ONE_TO_ONE
    } else {
        JoinMode::MANY_TO_MANY
    }
}

fn expr_to_column(expr: &Expr) -> Option<Column> {
    match expr {
        Expr::Column(col) => Some(col.clone()),
        Expr::Alias(alias) => expr_to_column(&alias.expr),
        Expr::Cast(cast) => expr_to_column(&cast.expr),
        Expr::TryCast(cast) => expr_to_column(&cast.expr),
        _ => None,
    }
}

fn collect_tables_from_schema(schema: &DFSchemaRef) -> HashSet<String> {
    schema
        .iter()
        .filter_map(|(qualifier, _)| qualifier.map(table_name_from_relation))
        .collect()
}

fn infer_table_from_schema(schema: &DFSchemaRef, col_name: &str) -> Option<String> {
    let candidates = schema
        .iter()
        .filter(|(_, field)| field.name() == col_name)
        .filter_map(|(qualifier, _)| qualifier.map(table_name_from_relation))
        .collect::<HashSet<_>>();
    single_table_name(&candidates)
}

fn single_table_name(tables: &HashSet<String>) -> Option<String> {
    if tables.len() == 1 {
        tables.iter().next().cloned()
    } else {
        None
    }
}

fn table_name_from_column(col: &Column) -> Option<String> {
    col.relation.as_ref().map(table_name_from_relation)
}

fn table_name_from_relation(relation: &TableReference) -> String {
    table_name_from_qualifier(&relation.to_string())
}

fn table_name_from_qualifier(qualifier: &str) -> String {
    qualifier
        .rsplit('.')
        .next()
        .unwrap_or(qualifier)
        .trim_matches('"')
        .trim_matches('`')
        .to_lowercase()
}
