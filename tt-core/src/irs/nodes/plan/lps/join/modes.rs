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
/// - composite join keys (`on.len() != 1`) => MANY_TO_MANY
/// - join filter present => MANY_TO_MANY
/// - if PK side has a Filter in its input subtree => MANY_TO_MANY
pub fn decide_join_mode(join: &Join) -> JoinMode {
    if join.join_type != JoinType::Inner {
        return dbg!(JoinMode::MANY_TO_MANY);
    }
    if join.on.len() != 1 || join.filter.is_some() {
        return dbg!(JoinMode::MANY_TO_MANY);
    }

    let Some(left_col) = expr_to_column(&join.on[0].0) else {
        return dbg!(JoinMode::MANY_TO_MANY);
    };
    let Some(right_col) = expr_to_column(&join.on[0].1) else {
        return dbg!(JoinMode::MANY_TO_MANY);
    };

    let left_schema = join.left.schema().clone();
    let right_schema = join.right.schema().clone();
    let left_meta = resolve_constraint_metadata(
        &left_schema,
        &left_col,
        table_name_from_column(&left_col).as_deref(),
    );
    let right_meta = resolve_constraint_metadata(
        &right_schema,
        &right_col,
        table_name_from_column(&right_col).as_deref(),
    );

    let Some(left_meta) = left_meta else {
        return dbg!(JoinMode::MANY_TO_MANY);
    };
    let Some(right_meta) = right_meta else {
        return dbg!(JoinMode::MANY_TO_MANY);
    };

    let left_col_name = left_col.name.to_lowercase();
    let right_col_name = right_col.name.to_lowercase();
    let left_table_name = table_name_from_column(&left_col);
    let right_table_name = table_name_from_column(&right_col);

    let left_is_fk_to_right = left_meta
        .fk_ref_table
        .as_deref()
        .zip(right_table_name.as_deref())
        .is_some_and(|(ref_table, right_table)| ref_table.eq_ignore_ascii_case(right_table))
        && left_meta
            .fk_ref_columns
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&right_col_name));
    let right_is_fk_to_left = right_meta
        .fk_ref_table
        .as_deref()
        .zip(left_table_name.as_deref())
        .is_some_and(|(ref_table, left_table)| ref_table.eq_ignore_ascii_case(left_table))
        && right_meta
            .fk_ref_columns
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&left_col_name));

    // left PK, right FK => output cardinality follows right side.
    if left_meta.is_pk && right_is_fk_to_left {
        if has_filter_in_subtree(&join.left) {
            return dbg!(JoinMode::MANY_TO_MANY);
        }
        return dbg!(JoinMode::ONE_TO_MANY);
    }
    // right PK, left FK => output cardinality follows left side.
    if right_meta.is_pk && left_is_fk_to_right {
        if has_filter_in_subtree(&join.right) {
            return dbg!(JoinMode::MANY_TO_MANY);
        }
        return dbg!(JoinMode::MANY_TO_ONE);
    }
    // Both sides unique and no filter on either side.
    if left_meta.is_pk && right_meta.is_pk {
        if has_filter_in_subtree(&join.left) || has_filter_in_subtree(&join.right) {
            return dbg!(JoinMode::MANY_TO_MANY);
        }
        return dbg!(JoinMode::ONE_TO_ONE);
    }

    dbg!(JoinMode::MANY_TO_MANY)
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
}

fn has_filter_in_subtree(plan: &LogicalPlan) -> bool {
    if matches!(plan, LogicalPlan::Filter(_)) {
        return true;
    }
    plan.inputs()
        .iter()
        .any(|input| has_filter_in_subtree(input))
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
