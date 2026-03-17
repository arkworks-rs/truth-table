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

#[cfg(test)]
mod tests {
    use super::{JoinMode, decide_join_mode};
    use arithmetic::ACTIVATOR_COL_NAME;
    use datafusion::arrow::{
        array::{BooleanArray, Int32Array, Int64Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use datafusion_common::{Column, TableReference};
    use datafusion_expr::{Expr, Join, JoinType, LogicalPlan, col, lit};
    use std::{collections::HashMap, sync::Arc};

    fn field_with_metadata(name: &str, metadata: &[(&str, &str)]) -> Field {
        let metadata = metadata
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<HashMap<_, _>>();
        Field::new(name, DataType::Int32, false).with_metadata(metadata)
    }

    fn build_df(
        ctx: &SessionContext,
        alias: &str,
        key_field: Field,
        value_field: Field,
    ) -> datafusion::prelude::DataFrame {
        let schema = Arc::new(Schema::new(vec![
            Field::new("row_id", DataType::Int64, false),
            key_field,
            value_field,
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int64Array::from(vec![0_i64, 1_i64])),
                Arc::new(Int32Array::from(vec![1_i32, 2_i32])),
                Arc::new(Int32Array::from(vec![10_i32, 20_i32])),
                Arc::new(BooleanArray::from(vec![true, true])),
            ],
        )
        .expect("test batch should build");
        ctx.read_batch(batch)
            .expect("test dataframe should build")
            .alias(alias)
            .expect("alias should succeed")
    }

    fn build_df_with_fields(
        ctx: &SessionContext,
        alias: &str,
        fields: Vec<Field>,
        columns: Vec<Arc<dyn datafusion::arrow::array::Array>>,
    ) -> datafusion::prelude::DataFrame {
        let schema = Arc::new(Schema::new(fields));
        let batch = RecordBatch::try_new(schema, columns).expect("test batch should build");
        ctx.read_batch(batch)
            .expect("test dataframe should build")
            .alias(alias)
            .expect("alias should succeed")
    }

    fn extract_join(plan: LogicalPlan) -> Join {
        match plan {
            LogicalPlan::Join(join) => join,
            other => panic!("expected join logical plan, found {other:?}"),
        }
    }

    fn qualified_col(relation: &str, name: &str) -> Expr {
        Expr::Column(Column::new(Some(TableReference::bare(relation)), name))
    }

    #[tokio::test]
    async fn detects_many_to_one_from_fk_to_pk_metadata() {
        let ctx = SessionContext::new();
        let customer = build_df(
            &ctx,
            "customer",
            field_with_metadata("custkey", &[("tt.pk", "true")]),
            Field::new("customer_val", DataType::Int32, false),
        );
        let orders = build_df(
            &ctx,
            "orders",
            field_with_metadata(
                "custkey",
                &[
                    ("tt.fk.ref_table", "customer"),
                    ("tt.fk.ref_columns", "[\"custkey\"]"),
                ],
            ),
            Field::new("orders_val", DataType::Int32, false),
        );

        let join = extract_join(
            orders
                .join_on(
                    customer,
                    JoinType::Inner,
                    vec![
                        qualified_col("orders", "custkey").eq(qualified_col("customer", "custkey")),
                    ],
                )
                .expect("join should build")
                .logical_plan()
                .clone(),
        );

        assert_eq!(decide_join_mode(&join), JoinMode::MANY_TO_ONE);
    }

    #[tokio::test]
    async fn detects_one_to_many_from_pk_to_fk_metadata() {
        let ctx = SessionContext::new();
        let supplier = build_df(
            &ctx,
            "supplier",
            field_with_metadata("suppkey", &[("tt.pk", "true")]),
            Field::new("supplier_val", DataType::Int32, false),
        );
        let lineitem = build_df(
            &ctx,
            "lineitem",
            field_with_metadata(
                "suppkey",
                &[
                    ("tt.fk.ref_table", "supplier"),
                    ("tt.fk.ref_columns", "[\"suppkey\"]"),
                ],
            ),
            Field::new("lineitem_val", DataType::Int32, false),
        );

        let join = extract_join(
            supplier
                .join_on(
                    lineitem,
                    JoinType::Inner,
                    vec![
                        qualified_col("supplier", "suppkey")
                            .eq(qualified_col("lineitem", "suppkey")),
                    ],
                )
                .expect("join should build")
                .logical_plan()
                .clone(),
        );

        assert_eq!(decide_join_mode(&join), JoinMode::ONE_TO_MANY);
    }

    #[tokio::test]
    async fn detects_one_to_one_when_both_sides_are_unique() {
        let ctx = SessionContext::new();
        let nation = build_df(
            &ctx,
            "nation",
            field_with_metadata("nationkey", &[("tt.pk", "true")]),
            Field::new("nation_val", DataType::Int32, false),
        );
        let region = build_df(
            &ctx,
            "region",
            field_with_metadata("regionkey", &[("tt.pk", "true")]),
            Field::new("region_val", DataType::Int32, false),
        );

        let join = extract_join(
            nation
                .join_on(
                    region,
                    JoinType::Inner,
                    vec![
                        qualified_col("nation", "nationkey")
                            .eq(qualified_col("region", "regionkey")),
                    ],
                )
                .expect("join should build")
                .logical_plan()
                .clone(),
        );

        assert_eq!(decide_join_mode(&join), JoinMode::ONE_TO_ONE);
    }

    #[tokio::test]
    async fn falls_back_to_many_to_many_when_pk_side_has_filter() {
        let ctx = SessionContext::new();
        let customer = build_df(
            &ctx,
            "customer",
            field_with_metadata("custkey", &[("tt.pk", "true")]),
            Field::new("customer_val", DataType::Int32, false),
        )
        .filter(col("customer_val").gt(lit(10_i32)))
        .expect("filter should build");
        let orders = build_df(
            &ctx,
            "orders",
            field_with_metadata(
                "custkey",
                &[
                    ("tt.fk.ref_table", "customer"),
                    ("tt.fk.ref_columns", "[\"custkey\"]"),
                ],
            ),
            Field::new("orders_val", DataType::Int32, false),
        );

        let join = extract_join(
            orders
                .join_on(
                    customer,
                    JoinType::Inner,
                    vec![
                        qualified_col("orders", "custkey").eq(qualified_col("customer", "custkey")),
                    ],
                )
                .expect("join should build")
                .logical_plan()
                .clone(),
        );

        assert_eq!(decide_join_mode(&join), JoinMode::MANY_TO_MANY);
    }

    #[tokio::test]
    async fn falls_back_to_many_to_many_when_fk_points_to_different_table() {
        let ctx = SessionContext::new();
        let customer = build_df(
            &ctx,
            "customer",
            field_with_metadata("custkey", &[("tt.pk", "true")]),
            Field::new("customer_val", DataType::Int32, false),
        );
        let orders = build_df(
            &ctx,
            "orders",
            field_with_metadata(
                "custkey",
                &[
                    ("tt.fk.ref_table", "nation"),
                    ("tt.fk.ref_columns", "[\"custkey\"]"),
                ],
            ),
            Field::new("orders_val", DataType::Int32, false),
        );

        let join = extract_join(
            orders
                .join_on(
                    customer,
                    JoinType::Inner,
                    vec![
                        qualified_col("orders", "custkey").eq(qualified_col("customer", "custkey")),
                    ],
                )
                .expect("join should build")
                .logical_plan()
                .clone(),
        );

        assert_eq!(decide_join_mode(&join), JoinMode::MANY_TO_MANY);
    }

    #[tokio::test]
    async fn detects_many_to_one_from_composite_fk_to_pk_metadata() {
        let ctx = SessionContext::new();
        let partsupp = build_df_with_fields(
            &ctx,
            "partsupp",
            vec![
                Field::new("row_id", DataType::Int64, false),
                field_with_metadata("partkey", &[("tt.pk", "true")]),
                field_with_metadata("suppkey", &[("tt.pk", "true")]),
                Field::new("partsupp_val", DataType::Int32, false),
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
            ],
            vec![
                Arc::new(Int64Array::from(vec![0_i64, 1_i64])),
                Arc::new(Int32Array::from(vec![1_i32, 2_i32])),
                Arc::new(Int32Array::from(vec![10_i32, 20_i32])),
                Arc::new(Int32Array::from(vec![100_i32, 200_i32])),
                Arc::new(BooleanArray::from(vec![true, true])),
            ],
        );
        let lineitem = build_df_with_fields(
            &ctx,
            "lineitem",
            vec![
                Field::new("row_id", DataType::Int64, false),
                field_with_metadata(
                    "partkey",
                    &[
                        ("tt.fk.ref_table", "partsupp"),
                        ("tt.fk.ref_columns", "[\"partkey\", \"suppkey\"]"),
                    ],
                ),
                field_with_metadata(
                    "suppkey",
                    &[
                        ("tt.fk.ref_table", "partsupp"),
                        ("tt.fk.ref_columns", "[\"partkey\", \"suppkey\"]"),
                    ],
                ),
                Field::new("lineitem_val", DataType::Int32, false),
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
            ],
            vec![
                Arc::new(Int64Array::from(vec![0_i64, 1_i64])),
                Arc::new(Int32Array::from(vec![1_i32, 2_i32])),
                Arc::new(Int32Array::from(vec![10_i32, 20_i32])),
                Arc::new(Int32Array::from(vec![7_i32, 8_i32])),
                Arc::new(BooleanArray::from(vec![true, true])),
            ],
        );

        let join = extract_join(
            lineitem
                .join_on(
                    partsupp,
                    JoinType::Inner,
                    vec![
                        qualified_col("lineitem", "partkey")
                            .eq(qualified_col("partsupp", "partkey")),
                        qualified_col("lineitem", "suppkey")
                            .eq(qualified_col("partsupp", "suppkey")),
                    ],
                )
                .expect("join should build")
                .logical_plan()
                .clone(),
        );

        assert_eq!(decide_join_mode(&join), JoinMode::MANY_TO_ONE);
    }

    #[tokio::test]
    async fn detects_one_to_many_from_composite_pk_to_fk_metadata() {
        let ctx = SessionContext::new();
        let partsupp = build_df_with_fields(
            &ctx,
            "partsupp",
            vec![
                Field::new("row_id", DataType::Int64, false),
                field_with_metadata("partkey", &[("tt.pk", "true")]),
                field_with_metadata("suppkey", &[("tt.pk", "true")]),
                Field::new("partsupp_val", DataType::Int32, false),
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
            ],
            vec![
                Arc::new(Int64Array::from(vec![0_i64, 1_i64])),
                Arc::new(Int32Array::from(vec![1_i32, 2_i32])),
                Arc::new(Int32Array::from(vec![10_i32, 20_i32])),
                Arc::new(Int32Array::from(vec![100_i32, 200_i32])),
                Arc::new(BooleanArray::from(vec![true, true])),
            ],
        );
        let lineitem = build_df_with_fields(
            &ctx,
            "lineitem",
            vec![
                Field::new("row_id", DataType::Int64, false),
                field_with_metadata(
                    "partkey",
                    &[
                        ("tt.fk.ref_table", "partsupp"),
                        ("tt.fk.ref_columns", "[\"partkey\", \"suppkey\"]"),
                    ],
                ),
                field_with_metadata(
                    "suppkey",
                    &[
                        ("tt.fk.ref_table", "partsupp"),
                        ("tt.fk.ref_columns", "[\"partkey\", \"suppkey\"]"),
                    ],
                ),
                Field::new("lineitem_val", DataType::Int32, false),
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
            ],
            vec![
                Arc::new(Int64Array::from(vec![0_i64, 1_i64])),
                Arc::new(Int32Array::from(vec![1_i32, 2_i32])),
                Arc::new(Int32Array::from(vec![10_i32, 20_i32])),
                Arc::new(Int32Array::from(vec![7_i32, 8_i32])),
                Arc::new(BooleanArray::from(vec![true, true])),
            ],
        );

        let join = extract_join(
            partsupp
                .join_on(
                    lineitem,
                    JoinType::Inner,
                    vec![
                        qualified_col("partsupp", "partkey")
                            .eq(qualified_col("lineitem", "partkey")),
                        qualified_col("partsupp", "suppkey")
                            .eq(qualified_col("lineitem", "suppkey")),
                    ],
                )
                .expect("join should build")
                .logical_plan()
                .clone(),
        );

        assert_eq!(decide_join_mode(&join), JoinMode::ONE_TO_MANY);
    }
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
    !metas.is_empty() && metas.iter().all(|meta| fk_ref_column_set(meta) == *other_col_names)
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
