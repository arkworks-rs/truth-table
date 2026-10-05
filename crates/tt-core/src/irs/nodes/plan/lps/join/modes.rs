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
    fk_ref_table: Option<String>,
    fk_ref_columns: Vec<String>,
}

/// Decide join mode directly from the logical join specification.
///
/// A specialized mode proves the join with a single lookup of the
/// foreign-key side's rows into the primary-key side (the PKFKJoin protocol),
/// so the verifier must be sure that every foreign-key row has at most one
/// match. That holds only when the primary-key side is a whole committed
/// table joined on its complete primary key; anything else falls back to
/// `MANY_TO_MANY`. Whether every foreign-key row has a match is a property of
/// the data owner's schema and affects only whether an honest proof exists.
///
/// Guards (any failing one yields `MANY_TO_MANY`):
/// - the join is inner, has equijoin keys, and has no extra filter;
/// - the two sides share no data column name (outputs are matched by name);
/// - the primary-key side is a plain scan of one table, see
///   [`plain_table_scan`], and the join keys are exactly its primary key;
/// - the foreign-key side's keys reference that table and it contains no
///   outer join (which could null a key).
///
/// `ONE_TO_ONE` is never chosen: it needs every key of one side to exist in
/// the other, which a primary key alone does not promise.
pub fn decide_join_mode(join: &Join) -> JoinMode {
    if join.join_type != JoinType::Inner {
        return JoinMode::MANY_TO_MANY;
    }
    if join.on.is_empty() || join.filter.is_some() {
        return JoinMode::MANY_TO_MANY;
    }
    if sides_share_column_names(join.left.schema(), join.right.schema()) {
        return JoinMode::MANY_TO_MANY;
    }

    let mut left_cols = Vec::with_capacity(join.on.len());
    let mut right_cols = Vec::with_capacity(join.on.len());
    for (left_expr, right_expr) in &join.on {
        let (Some(left_col), Some(right_col)) =
            (expr_to_column(left_expr), expr_to_column(right_expr))
        else {
            return JoinMode::MANY_TO_MANY;
        };
        left_cols.push(left_col);
        right_cols.push(right_col);
    }

    // left PK, right FK => output cardinality follows right side.
    if let Some(pk_table) = unique_key_table(&join.left, &left_cols)
        && is_foreign_key_side(&join.right, &right_cols, &pk_table, &left_cols)
    {
        return JoinMode::ONE_TO_MANY;
    }
    // right PK, left FK => output cardinality follows left side.
    if let Some(pk_table) = unique_key_table(&join.right, &right_cols)
        && is_foreign_key_side(&join.left, &left_cols, &pk_table, &right_cols)
    {
        return JoinMode::MANY_TO_ONE;
    }
    JoinMode::MANY_TO_MANY
}

/// Returns the base table name when `plan` is a plain scan of one table and
/// `key_cols` are exactly that table's primary key, so each key value names at
/// most one active row.
fn unique_key_table(plan: &LogicalPlan, key_cols: &[Column]) -> Option<String> {
    let (scan, aliases) = plain_table_scan(plan)?;
    let table = scan.table_name.table().to_lowercase();
    let names_this_table = |col: &Column| {
        col.relation.as_ref().is_none_or(|relation| {
            let relation = table_name_from_relation(relation);
            relation == table || aliases.contains(&relation)
        })
    };
    if !key_cols.iter().all(names_this_table) {
        return None;
    }
    let primary_key = primary_key_columns(scan)?;
    (!primary_key.is_empty() && column_name_set(key_cols) == primary_key).then_some(table)
}

/// Unwraps `plan` down to a table scan when every row of the scan reaches the
/// output unchanged: only aliases, column-only projections that keep each
/// column's name, and a scan with no pushed-down filter or row limit. Returns
/// the scan and the aliases seen on the way.
fn plain_table_scan(plan: &LogicalPlan) -> Option<(&datafusion_expr::TableScan, BTreeSet<String>)> {
    let mut aliases = BTreeSet::new();
    let mut current = plan;
    loop {
        match current {
            LogicalPlan::SubqueryAlias(alias) => {
                aliases.insert(table_name_from_relation(&alias.alias));
                current = alias.input.as_ref();
            }
            LogicalPlan::Projection(projection) => {
                if !projection.expr.iter().all(is_name_preserving_column) {
                    return None;
                }
                current = projection.input.as_ref();
            }
            LogicalPlan::TableScan(scan) => {
                return (scan.filters.is_empty() && scan.fetch.is_none())
                    .then_some((scan, aliases));
            }
            _ => return None,
        }
    }
}

fn is_name_preserving_column(expr: &Expr) -> bool {
    match expr {
        Expr::Column(_) => true,
        Expr::Alias(alias) => {
            matches!(alias.expr.as_ref(), Expr::Column(col) if col.name == alias.name)
        }
        _ => false,
    }
}

/// The primary key the data owner declared for the scanned table. A verifier
/// reads it from the committed schema's metadata; a prover whose parquet schema
/// carries no metadata reads the same `constraints.json` the commitment was
/// built from.
fn primary_key_columns(scan: &datafusion_expr::TableScan) -> Option<BTreeSet<String>> {
    let schema = scan.source.schema();
    let has_constraint_metadata = schema
        .fields()
        .iter()
        .any(|field| field.metadata().keys().any(|key| key.starts_with("tt.")));
    if has_constraint_metadata {
        return Some(
            schema
                .fields()
                .iter()
                .filter(|field| {
                    field
                        .metadata()
                        .get(PK_METADATA_KEY)
                        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
                })
                .map(|field| field.name().to_lowercase())
                .collect(),
        );
    }
    crate::irs::nodes::hints::table_primary_key_columns(scan.table_name.table())
}

/// Whether `fk_cols` of `plan` are a foreign key into `pk_table`'s `pk_cols`.
/// This decides only completeness (every row finds its match), not soundness.
fn is_foreign_key_side(
    plan: &LogicalPlan,
    fk_cols: &[Column],
    pk_table: &str,
    pk_cols: &[Column],
) -> bool {
    if has_outer_join(plan) {
        return false;
    }
    let pk_names = column_name_set(pk_cols);
    fk_cols.iter().all(|col| {
        let base_table = col.relation.as_ref().and_then(|relation| {
            base_table_for_relation(plan, &table_name_from_relation(relation))
        });
        let Some(meta) = resolve_constraint_metadata(plan.schema(), col, base_table.as_deref())
        else {
            return false;
        };
        meta.fk_ref_table
            .as_deref()
            .is_some_and(|ref_table| table_name_from_qualifier(ref_table) == pk_table)
            && fk_ref_column_set(&meta) == pk_names
    })
}

fn has_outer_join(plan: &LogicalPlan) -> bool {
    if let LogicalPlan::Join(join) = plan
        && join.join_type != JoinType::Inner
    {
        return true;
    }
    plan.inputs().iter().any(|input| has_outer_join(input))
}

/// Resolves a column qualifier (a table name or an alias) to the name of the
/// table scanned under it.
fn base_table_for_relation(plan: &LogicalPlan, relation: &str) -> Option<String> {
    match plan {
        LogicalPlan::TableScan(scan) => {
            let table = scan.table_name.table().to_lowercase();
            (table == relation).then_some(table)
        }
        LogicalPlan::SubqueryAlias(alias) if table_name_from_relation(&alias.alias) == relation => {
            first_scanned_table(&alias.input)
        }
        _ => plan
            .inputs()
            .iter()
            .find_map(|input| base_table_for_relation(input, relation)),
    }
}

fn first_scanned_table(plan: &LogicalPlan) -> Option<String> {
    match plan {
        LogicalPlan::TableScan(scan) => Some(scan.table_name.table().to_lowercase()),
        _ => match plan.inputs().as_slice() {
            [input] => first_scanned_table(input),
            _ => None,
        },
    }
}

fn sides_share_column_names(left: &DFSchemaRef, right: &DFSchemaRef) -> bool {
    let data_names = |schema: &DFSchemaRef| {
        schema
            .fields()
            .iter()
            .map(|field| field.name().to_lowercase())
            .filter(|name| !arithmetic::is_system_column(name))
            .collect::<BTreeSet<_>>()
    };
    !data_names(left).is_disjoint(&data_names(right))
}

fn column_name_set(columns: &[Column]) -> BTreeSet<String> {
    columns.iter().map(|col| col.name.to_lowercase()).collect()
}

fn fk_ref_column_set(meta: &ColumnConstraintMetadata) -> BTreeSet<String> {
    meta.fk_ref_columns
        .iter()
        .map(|col| col.to_lowercase())
        .collect()
}

pub(crate) fn expr_to_column(expr: &Expr) -> Option<Column> {
    match expr {
        Expr::Column(col) => Some(col.clone()),
        Expr::Alias(alias) => expr_to_column(&alias.expr),
        Expr::Cast(cast) => expr_to_column(&cast.expr),
        Expr::TryCast(cast) => expr_to_column(&cast.expr),
        _ => None,
    }
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
    let fk_ref_table = metadata.get(FK_REF_TABLE_METADATA_KEY).cloned();
    let fk_ref_columns = metadata
        .get(FK_REF_COLUMNS_METADATA_KEY)
        .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
        .unwrap_or_default();

    if fk_ref_table.is_none() && fk_ref_columns.is_empty() {
        return None;
    }
    Some(ColumnConstraintMetadata {
        fk_ref_table,
        fk_ref_columns,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_expr::{
        JoinType, LogicalPlanBuilder, col, lit,
        logical_plan::{builder::table_scan_with_filters, table_scan},
    };

    use super::*;

    /// A column carrying the constraint metadata a committed table has.
    fn field(table: &str, name: &str, pk: bool, fk: Option<(&str, &[&str])>) -> Field {
        let mut metadata = HashMap::from([(QUALIFIER_METADATA_KEY.to_string(), table.to_string())]);
        if pk {
            metadata.insert(PK_METADATA_KEY.to_string(), "true".to_string());
        }
        if let Some((ref_table, ref_cols)) = fk {
            metadata.insert(FK_REF_TABLE_METADATA_KEY.to_string(), ref_table.to_string());
            metadata.insert(
                FK_REF_COLUMNS_METADATA_KEY.to_string(),
                serde_json::to_string(ref_cols).unwrap(),
            );
        }
        Field::new(name, DataType::Int64, false).with_metadata(metadata)
    }

    fn nation() -> LogicalPlanBuilder {
        let schema = Schema::new(vec![
            field("nation", "n_nationkey", true, None),
            field("nation", "n_regionkey", false, None),
        ]);
        table_scan(Some("nation"), &schema, None).unwrap()
    }

    fn supplier() -> LogicalPlanBuilder {
        let schema = Schema::new(vec![
            field("supplier", "s_suppkey", true, None),
            field(
                "supplier",
                "s_nationkey",
                false,
                Some(("nation", &["n_nationkey"])),
            ),
        ]);
        table_scan(Some("supplier"), &schema, None).unwrap()
    }

    /// `lineitem` keyed by `(l_orderkey, l_linenumber)`.
    fn lineitem() -> LogicalPlanBuilder {
        let schema = Schema::new(vec![
            field("lineitem", "l_orderkey", true, None),
            field("lineitem", "l_linenumber", true, None),
        ]);
        table_scan(Some("lineitem"), &schema, None).unwrap()
    }

    fn orders_referencing_lineitem() -> LogicalPlanBuilder {
        let schema = Schema::new(vec![field(
            "orders",
            "o_orderkey",
            true,
            Some(("lineitem", &["l_orderkey"])),
        )]);
        table_scan(Some("orders"), &schema, None).unwrap()
    }

    fn mode(left: LogicalPlanBuilder, right: LogicalPlanBuilder, on: (&str, &str)) -> JoinMode {
        let plan = left
            .join(
                right.build().unwrap(),
                JoinType::Inner,
                (vec![on.0], vec![on.1]),
                None,
            )
            .unwrap()
            .build()
            .unwrap();
        let LogicalPlan::Join(join) = plan else {
            unreachable!("the builder produced a join");
        };
        decide_join_mode(&join)
    }

    #[test]
    fn an_fk_into_a_whole_table_specializes() {
        let on = ("supplier.s_nationkey", "nation.n_nationkey");
        assert_eq!(mode(supplier(), nation(), on), JoinMode::MANY_TO_ONE);
        let on = ("nation.n_nationkey", "supplier.s_nationkey");
        assert_eq!(mode(nation(), supplier(), on), JoinMode::ONE_TO_MANY);
    }

    #[test]
    fn aliases_resolve_to_their_tables() {
        let s = supplier().alias("s").unwrap();
        let n = nation().alias("n").unwrap();
        assert_eq!(
            mode(s, n, ("s.s_nationkey", "n.n_nationkey")),
            JoinMode::MANY_TO_ONE
        );
    }

    #[test]
    fn a_filtered_pk_side_does_not_specialize() {
        let on = ("supplier.s_nationkey", "nation.n_nationkey");
        let filtered = nation().filter(col("n_regionkey").eq(lit(1_i64))).unwrap();
        assert_eq!(mode(supplier(), filtered, on), JoinMode::MANY_TO_MANY);

        let schema = nation().schema().as_arrow().clone();
        let pushed_down = table_scan_with_filters(
            Some("nation"),
            &schema,
            None,
            vec![col("n_regionkey").eq(lit(1_i64))],
        )
        .unwrap();
        assert_eq!(mode(supplier(), pushed_down, on), JoinMode::MANY_TO_MANY);
    }

    #[test]
    fn a_renamed_pk_side_column_does_not_specialize() {
        // `n_regionkey AS n_nationkey` is not unique even though its name is.
        let renamed = nation()
            .project(vec![col("n_regionkey").alias("n_nationkey")])
            .unwrap();
        let on = ("supplier.s_nationkey", "n_nationkey");
        assert_eq!(mode(supplier(), renamed, on), JoinMode::MANY_TO_MANY);
    }

    #[test]
    fn part_of_a_composite_key_does_not_specialize() {
        let on = ("orders.o_orderkey", "lineitem.l_orderkey");
        assert_eq!(
            mode(orders_referencing_lineitem(), lineitem(), on),
            JoinMode::MANY_TO_MANY
        );
    }

    #[test]
    fn an_outer_join_on_the_fk_side_does_not_specialize() {
        let outer = supplier()
            .join(
                lineitem().build().unwrap(),
                JoinType::Left,
                (vec!["supplier.s_suppkey"], vec!["lineitem.l_orderkey"]),
                None,
            )
            .unwrap();
        let on = ("supplier.s_nationkey", "nation.n_nationkey");
        assert_eq!(mode(outer, nation(), on), JoinMode::MANY_TO_MANY);
    }
}
