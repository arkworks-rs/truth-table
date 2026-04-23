use std::collections::BTreeSet;

use datafusion_common::{Column, DFSchemaRef, TableReference};
use datafusion_expr::{Expr, Join, JoinType, LogicalPlan};

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

#[derive(Clone, Debug, Default)]
struct ColumnConstraintMetadata {
    is_pk: bool,
    fk_ref_table: Option<String>,
    fk_ref_columns: Vec<String>,
}

/// Decide join mode directly from the logical join specification.
///
/// Correctness guards:
/// - non-inner joins => MANY_TO_MANY
/// - no equijoin keys => MANY_TO_MANY
/// - join filter present => MANY_TO_MANY
/// - if PK side has a Filter in its input subtree => MANY_TO_MANY
pub fn decide_join_mode(join: &Join) -> JoinMode {
    if join.join_type != JoinType::Inner {
        return JoinMode::MANY_TO_MANY;
    }
    if join.on.is_empty() || join.filter.is_some() {
        return JoinMode::MANY_TO_MANY;
    }

    let left_schema = join.left.schema().clone();
    let right_schema = join.right.schema().clone();
    let mut left_cols = Vec::with_capacity(join.on.len());
    let mut right_cols = Vec::with_capacity(join.on.len());
    let mut left_metas = Vec::with_capacity(join.on.len());
    let mut right_metas = Vec::with_capacity(join.on.len());

    for (left_expr, right_expr) in &join.on {
        let Some(left_col) = expr_to_column(left_expr) else {
            return JoinMode::MANY_TO_MANY;
        };
        let Some(right_col) = expr_to_column(right_expr) else {
            return JoinMode::MANY_TO_MANY;
        };

        let Some(left_meta) = resolve_constraint_metadata(
            &left_schema,
            &left_col,
            table_name_from_column(&left_col).as_deref(),
        ) else {
            return JoinMode::MANY_TO_MANY;
        };
        let Some(right_meta) = resolve_constraint_metadata(
            &right_schema,
            &right_col,
            table_name_from_column(&right_col).as_deref(),
        ) else {
            return JoinMode::MANY_TO_MANY;
        };

        left_cols.push(left_col);
        right_cols.push(right_col);
        left_metas.push(left_meta);
        right_metas.push(right_meta);
    }

    let left_col_names = column_name_set(&left_cols);
    let right_col_names = column_name_set(&right_cols);
    let left_table_name = unique_table_name(&left_cols);
    let right_table_name = unique_table_name(&right_cols);

    let left_is_fk_to_right =
        all_columns_form_fk_to_table(&left_metas, right_table_name.as_deref(), &right_col_names)
            || all_columns_form_fk_to_column_set(&left_metas, &right_col_names);
    let right_is_fk_to_left =
        all_columns_form_fk_to_table(&right_metas, left_table_name.as_deref(), &left_col_names)
            || all_columns_form_fk_to_column_set(&right_metas, &left_col_names);
    let left_all_pk = left_metas.iter().all(|meta| meta.is_pk);
    let right_all_pk = right_metas.iter().all(|meta| meta.is_pk);

    // left PK, right FK => output cardinality follows right side.
    if left_all_pk && right_is_fk_to_left {
        if has_filter_in_subtree(&join.left) {
            return JoinMode::MANY_TO_MANY;
        }
        return JoinMode::ONE_TO_MANY;
    }
    // right PK, left FK => output cardinality follows left side.
    if right_all_pk && left_is_fk_to_right {
        if has_filter_in_subtree(&join.right) {
            return JoinMode::MANY_TO_MANY;
        }
        return JoinMode::MANY_TO_ONE;
    }
    // Single-column PK-to-PK joins are one-to-one.
    if join.on.len() == 1 && left_all_pk && right_all_pk {
        if has_filter_in_subtree(&join.left) || has_filter_in_subtree(&join.right) {
            return JoinMode::MANY_TO_MANY;
        }
        return JoinMode::ONE_TO_ONE;
    }

    JoinMode::MANY_TO_MANY
}

fn has_filter_in_subtree(plan: &LogicalPlan) -> bool {
    if matches!(plan, LogicalPlan::Filter(_)) {
        return true;
    }
    plan.inputs()
        .iter()
        .any(|input| has_filter_in_subtree(input))
}

fn column_name_set(columns: &[Column]) -> BTreeSet<String> {
    columns.iter().map(|col| col.name.to_lowercase()).collect()
}

fn unique_table_name(columns: &[Column]) -> Option<String> {
    let mut tables = columns
        .iter()
        .filter_map(table_name_from_column)
        .collect::<BTreeSet<_>>();
    if tables.len() == 1 {
        tables.pop_first()
    } else {
        None
    }
}

fn all_columns_form_fk_to_table(
    metas: &[ColumnConstraintMetadata],
    other_table_name: Option<&str>,
    other_col_names: &BTreeSet<String>,
) -> bool {
    let Some(other_table_name) = other_table_name else {
        return false;
    };
    !metas.is_empty()
        && metas.iter().all(|meta| {
            meta.fk_ref_table
                .as_deref()
                .is_some_and(|ref_table| ref_table.eq_ignore_ascii_case(other_table_name))
                && fk_ref_column_set(meta) == *other_col_names
        })
}

fn all_columns_form_fk_to_column_set(
    metas: &[ColumnConstraintMetadata],
    other_col_names: &BTreeSet<String>,
) -> bool {
    !metas.is_empty()
        && metas
            .iter()
            .all(|meta| fk_ref_column_set(meta) == *other_col_names)
}

fn fk_ref_column_set(meta: &ColumnConstraintMetadata) -> BTreeSet<String> {
    meta.fk_ref_columns
        .iter()
        .map(|col| col.to_lowercase())
        .collect()
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
    let table = fallback_table?;
    crate::irs::nodes::hints::column_constraint_metadata(table, col.name.as_str()).map(|m| {
        ColumnConstraintMetadata {
            is_pk: m.is_pk,
            fk_ref_table: m.fk_ref_table,
            fk_ref_columns: m.fk_ref_columns,
        }
    })
}

fn constraint_metadata_from_field(
    schema: &DFSchemaRef,
    col: &Column,
) -> Option<ColumnConstraintMetadata> {
    let field = schema.iter().find_map(|(qualifier, field)| {
        if field.name() != col.name.as_str() {
            return None;
        }
        match (&col.relation, qualifier) {
            (Some(rel), Some(q)) => {
                let rel_name = table_name_from_relation(rel);
                let qual_name = table_name_from_relation(q);
                if rel_name == qual_name {
                    return Some(field.as_ref().clone());
                }
                field
                    .metadata()
                    .get(QUALIFIER_METADATA_KEY)
                    .and_then(|m| (table_name_from_qualifier(m) == rel_name).then_some(field))
                    .map(|f| f.as_ref().clone())
            }
            (Some(rel), None) => {
                let rel_name = table_name_from_relation(rel);
                field
                    .metadata()
                    .get(QUALIFIER_METADATA_KEY)
                    .and_then(|m| (table_name_from_qualifier(m) == rel_name).then_some(field))
                    .map(|f| f.as_ref().clone())
            }
            (None, _) => Some(field.as_ref().clone()),
        }
    })?;

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
