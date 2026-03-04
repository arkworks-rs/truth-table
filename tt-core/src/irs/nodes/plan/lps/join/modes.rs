use std::collections::HashSet;

use crate::irs::nodes::hints::{ColumnConstraintMetadata, column_constraint_metadata};
use datafusion_common::{Column, DFSchemaRef, TableReference};
use datafusion_expr::{Expr, Join, JoinType};

const PK_METADATA_KEY: &str = "tt.pk";
const FK_REF_TABLE_METADATA_KEY: &str = "tt.fk.ref_table";
const FK_REF_COLUMNS_METADATA_KEY: &str = "tt.fk.ref_columns";
const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";

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
    // HasOne optimization path currently assumes INNER semantics over the FK-side domain.
    // Keep all other join types on the conservative many-to-many path.
    if !matches!(join.join_type, JoinType::Inner) {
        return JoinMode::MANY_TO_MANY;
    };
    if join.on.is_empty() {
        return JoinMode::MANY_TO_MANY;
    }

    let left_schema = join.left.schema();
    let right_schema = join.right.schema();
    let left_tables = collect_tables_from_schema(left_schema);
    let right_tables = collect_tables_from_schema(right_schema);

    let mut left_is_pk_all = true;
    let mut right_is_pk_all = true;
    let mut left_is_fk_to_right_all = true;
    let mut right_is_fk_to_left_all = true;

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

        let Some(left_meta) =
            resolve_constraint_metadata(left_schema, &left_col, left_table.as_deref())
        else {
            return JoinMode::MANY_TO_MANY;
        };
        let Some(right_meta) =
            resolve_constraint_metadata(right_schema, &right_col, right_table.as_deref())
        else {
            return JoinMode::MANY_TO_MANY;
        };

        left_is_pk_all &= left_meta.is_pk;
        right_is_pk_all &= right_meta.is_pk;

        let left_fk_to_right = left_meta
            .fk_ref_table
            .as_ref()
            .map(|ref_table| {
                right_table
                    .as_deref()
                    .map(|t| table_name_from_qualifier(ref_table) == t)
                    .unwrap_or(false)
                    && left_meta
                        .fk_ref_columns
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(right_col.name.as_str()))
            })
            .unwrap_or(false);
        let right_fk_to_left = right_meta
            .fk_ref_table
            .as_ref()
            .map(|ref_table| {
                left_table
                    .as_deref()
                    .map(|t| table_name_from_qualifier(ref_table) == t)
                    .unwrap_or(false)
                    && right_meta
                        .fk_ref_columns
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(left_col.name.as_str()))
            })
            .unwrap_or(false);

        left_is_fk_to_right_all &= left_fk_to_right;
        right_is_fk_to_left_all &= right_fk_to_left;
    }

    // Prefer explicit PK/FK direction first.
    if left_is_pk_all && right_is_fk_to_left_all {
        JoinMode::ONE_TO_MANY
    } else if right_is_pk_all && left_is_fk_to_right_all {
        JoinMode::MANY_TO_ONE
    // Conservative fallback for pure PK=PK joins. The current partial-join path
    // is tuned for PK/FK semantics and can violate row-domain invariants on some
    // queries when used as generic 1-1 optimization.
    } else if left_is_pk_all && right_is_pk_all {
        JoinMode::MANY_TO_MANY
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

fn resolve_constraint_metadata(
    schema: &DFSchemaRef,
    col: &Column,
    fallback_table: Option<&str>,
) -> Option<ColumnConstraintMetadata> {
    if let Some(meta) = constraint_metadata_from_field(schema, col) {
        return Some(meta);
    }
    fallback_table.and_then(|tbl| column_constraint_metadata(tbl, col.name.as_str()))
}

fn constraint_metadata_from_field(
    schema: &DFSchemaRef,
    col: &Column,
) -> Option<ColumnConstraintMetadata> {
    let exact_matching_fields = schema
        .iter()
        .filter(|(qualifier, field)| {
            if field.name() != col.name.as_str() {
                return false;
            }
            match (&col.relation, qualifier) {
                (Some(rel), Some(q)) => {
                    let rel_name = table_name_from_relation(rel);
                    let qual_name = table_name_from_relation(q);
                    if rel_name == qual_name {
                        return true;
                    }
                    field
                        .metadata()
                        .get(QUALIFIER_METADATA_KEY)
                        .map(|m| table_name_from_qualifier(m) == rel_name)
                        .unwrap_or(false)
                }
                (Some(rel), None) => {
                    let rel_name = table_name_from_relation(rel);
                    field
                        .metadata()
                        .get(QUALIFIER_METADATA_KEY)
                        .map(|m| table_name_from_qualifier(m) == rel_name)
                        .unwrap_or(false)
                }
                (None, _) => true,
            }
        })
        .map(|(_, field)| field)
        .collect::<Vec<_>>();

    let matching_fields = if exact_matching_fields.len() == 1 {
        exact_matching_fields
    } else {
        if col.relation.is_some() {
            return None;
        }
        // In planned schemas qualifiers can be rewritten (e.g., aliases or "?table?").
        // Fall back to a unique match by field name to keep PK/FK propagation usable
        // across chained joins.
        let by_name = schema
            .iter()
            .filter(|(_, field)| field.name() == col.name.as_str())
            .map(|(_, field)| field)
            .collect::<Vec<_>>();
        if by_name.len() != 1 {
            return None;
        }
        by_name
    };

    let field = matching_fields[0];
    let metadata = field.metadata();

    let is_pk = metadata
        .get(PK_METADATA_KEY)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let fk_ref_table = metadata.get(FK_REF_TABLE_METADATA_KEY).cloned();
    let fk_ref_columns = metadata
        .get(FK_REF_COLUMNS_METADATA_KEY)
        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
        .unwrap_or_default();

    if !is_pk && fk_ref_table.is_none() && fk_ref_columns.is_empty() {
        return None;
    }
    Some(ColumnConstraintMetadata {
        is_pk,
        fk_ref_table,
        fk_ref_columns,
    })
}
