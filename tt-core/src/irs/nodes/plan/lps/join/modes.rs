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
    let _ = join;
    JoinMode::MANY_TO_MANY
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
