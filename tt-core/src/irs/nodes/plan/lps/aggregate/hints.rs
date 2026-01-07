use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_expr::{
    Aggregate, Expr, ExprFunctionExt, JoinType, col, expr::Sort as SortExpr, expr_fn::when, lit,
};
/// Expand an aggregate so that:
/// - only active rows contribute to the aggregate
/// - all rows keep their row-level detail, with aggregate values duplicated
/// - exactly one active row per group is marked as the representative (activator = true)
/// - all other rows (including originally inactive ones) have activator = false
pub(super) fn build_output_dataframe(input: &DataFrame, aggregate: &Aggregate) -> DataFrame {
    // 0. Make the original activator explicit so we don’t lose it
    let df = input
        .clone()
        .with_column_renamed(ACTIVATOR_COL_NAME, "__activator_orig__")
        .unwrap();

    // 1. Aggregate only over active rows
    let active_df = df.clone().filter(col("__activator_orig__")).unwrap();
    // 2. Join aggregates back to *all* rows.
    //
    // For simplicity, assume group_exprs are plain column refs,
    // e.g. vec![col("group_col1"), col("group_col2")].
    // Then we can extract the column names for the join:
    let group_cols: Vec<String> = aggregate
        .group_expr
        .iter()
        .map(|e| match e {
            Expr::Column(c) => c.name.clone(),
            _ => panic!("Non-column group exprs require a pre-aggregate step"),
        })
        .collect();
    let agg_df = active_df
        .aggregate(aggregate.group_expr.clone(), aggregate.aggr_expr.clone())
        .unwrap();
    let agg_group_cols: Vec<String> = group_cols
        .iter()
        .enumerate()
        .map(|(idx, name)| format!("__agg_group_{idx}_{name}"))
        .collect();
    let mut renamed_agg_df = agg_df;
    for (original, renamed) in group_cols.iter().zip(agg_group_cols.iter()) {
        renamed_agg_df = renamed_agg_df
            .with_column_renamed(original, renamed)
            .unwrap();
    }

    let group_cols_str: Vec<&str> = group_cols.iter().map(|s| s.as_str()).collect();
    let agg_group_cols_str: Vec<&str> = agg_group_cols.iter().map(|s| s.as_str()).collect();
    let joined = df
        .join(
            renamed_agg_df,
            JoinType::Left,
            &group_cols_str,
            &agg_group_cols_str,
            None,
        )
        .unwrap();

    // 3. Use a window function to pick a group representative
    //
    // We want: “first active row in each group” to keep activator = true.
    // Others become false.
    //
    // row_number() OVER (PARTITION BY group_exprs ORDER BY nothing)
    // and then:
    //   new_activator = (orig_activator && row_number == 1)
    let mut row_number_builder = row_number().partition_by(aggregate.group_expr.clone());
    if input
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        row_number_builder =
            row_number_builder.order_by(vec![col(ROW_ID_COL_NAME).sort(true, true)]);
    }
    let window_expr = row_number_builder
        .build()
        .expect("partitioned row_number window should build")
        .alias("__row_number__");
    let with_rownum = joined.window(vec![window_expr]).unwrap();
    // 4. Define the new activator:
    // new __activator__ = __activator_orig__ && __row_number__ == 1

    let new_activator_expr = when(
        col("__activator_orig__").and(col("__row_number__").eq(lit(1_i64))),
        lit(true),
    )
    .otherwise(lit(false))
    .expect("case expression creation should succeed");

    let with_new_activator = with_rownum
        .with_column("__activator__", new_activator_expr)
        .unwrap();
    // To keep deterministic output across executions, order the rows by the
    // grouping columns (if any) and then by the representative flag.
    let mut sort_exprs: Vec<SortExpr> = aggregate
        .group_expr
        .iter()
        .map(|expr| expr.clone().sort(true, true))
        .collect();
    if input
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        sort_exprs.push(col(ROW_ID_COL_NAME).sort(true, true));
    }
    sort_exprs.push(col("__row_number__").sort(true, true));
    let sorted = with_new_activator.sort(sort_exprs).unwrap();
    let mut drop_columns: Vec<&str> = agg_group_cols.iter().map(|s| s.as_str()).collect();
    drop_columns.push("__row_number__");
    drop_columns.push("__activator_orig__");
    sorted.drop_columns(&drop_columns).unwrap()
}

#[cfg(test)]
mod tests {
    use super::build_output_dataframe;
    use arithmetic::ACTIVATOR_COL_NAME;
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Date32Array, Int32Array, Int64Array},
        compute::concat_batches,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use datafusion_expr::{Expr, LogicalPlan, col};
    use datafusion_functions_aggregate::expr_fn::{count, max, sum};
    use std::sync::Arc;

    async fn run_aggregate_test(
        ctx: &SessionContext,
        input_columns: &[(Field, ArrayRef)],
        group_exprs: &[Expr],
        aggr_exprs: &[Expr],
        expected_columns: &[(Field, ArrayRef)],
    ) {
        // Build a single input RecordBatch from the provided columns so the test
        // matches exactly the data passed to the DataFrame.
        let input_schema = Arc::new(Schema::new(
            input_columns
                .iter()
                .map(|(field, _)| field.clone())
                .collect::<Vec<_>>(),
        ));
        let input_batch = RecordBatch::try_new(
            Arc::clone(&input_schema),
            input_columns
                .iter()
                .map(|(_, array)| Arc::clone(array))
                .collect(),
        )
        .expect("input batch construction should succeed");
        let input_df = ctx
            .read_batch(input_batch)
            .expect("failed to read batch into DataFrame");

        // Build a real Aggregate logical plan via DataFusion so we exercise the
        // same code that the production pipeline uses.
        let aggregate_plan = input_df
            .clone()
            .aggregate(group_exprs.to_vec(), aggr_exprs.to_vec())
            .expect("aggregate creation should succeed")
            .into_unoptimized_plan();
        let LogicalPlan::Aggregate(aggregate) = aggregate_plan else {
            panic!("expected aggregate logical plan");
        };

        let projected = build_output_dataframe(&input_df, &aggregate);
        let batches = projected.collect().await.unwrap();
        // Expected batch uses the exact schema/values we want to observe.
        let expected_schema = Arc::new(Schema::new(
            expected_columns
                .iter()
                .map(|(field, _)| field.clone())
                .collect::<Vec<_>>(),
        ));
        let expected_batch = RecordBatch::try_new(
            expected_schema,
            expected_columns
                .iter()
                .map(|(_, array)| Arc::clone(array))
                .collect(),
        )
        .expect("expected batch construction should succeed");
        let combined_batch =
            concat_batches(&batches[0].schema(), &batches).expect("concat batches");
        assert_eq!(combined_batch, expected_batch);
    }

    #[tokio::test]
    async fn aggregate_node_count_output_is_correct() {
        let ctx = SessionContext::new();

        let input_columns = vec![
            (
                Field::new("group_id", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 0, 1, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("value", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![10, 20, 30, 40, 50, 60])) as ArrayRef,
            ),
            (
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                Arc::new(BooleanArray::from(vec![
                    true, true, false, true, false, true,
                ])) as ArrayRef,
            ),
        ];

        let expected_columns = vec![
            (
                Field::new("group_id", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 0, 1, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("value", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![10, 20, 30, 40, 50, 60])) as ArrayRef,
            ),
            (
                Field::new("active_count", DataType::Int64, true),
                Arc::new(Int64Array::from(vec![2, 2, 2, 2, 2, 2])) as ArrayRef,
            ),
            (
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                Arc::new(BooleanArray::from(vec![
                    true, false, false, true, false, false,
                ])) as ArrayRef,
            ),
        ];

        run_aggregate_test(
            &ctx,
            &input_columns,
            &[col("group_id")],
            &[count(col("value")).alias("active_count")],
            &expected_columns,
        )
        .await;
    }

    #[tokio::test]
    async fn aggregate_node_sum_output_is_correct() {
        let ctx = SessionContext::new();

        let input_columns = vec![
            (
                Field::new("group_id", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 0, 1, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("sub_group", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 1, 0, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("value", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![5, 15, 25, 10, 20, 30])) as ArrayRef,
            ),
            (
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                Arc::new(BooleanArray::from(vec![
                    true, false, true, true, true, true,
                ])) as ArrayRef,
            ),
        ];

        let expected_columns = vec![
            (
                Field::new("group_id", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 0, 1, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("sub_group", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 1, 0, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("value", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![5, 15, 25, 10, 20, 30])) as ArrayRef,
            ),
            (
                Field::new("active_sum", DataType::Int64, true),
                Arc::new(Int64Array::from(vec![5, 5, 25, 10, 50, 50])) as ArrayRef,
            ),
            (
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                Arc::new(BooleanArray::from(vec![
                    true, false, true, true, true, false,
                ])) as ArrayRef,
            ),
        ];

        run_aggregate_test(
            &ctx,
            &input_columns,
            &[col("group_id"), col("sub_group")],
            &[sum(col("value")).alias("active_sum")],
            &expected_columns,
        )
        .await;
    }

    #[tokio::test]
    async fn aggregate_node_max_output_is_correct() {
        let ctx = SessionContext::new();

        let input_columns = vec![
            (
                Field::new("group_id", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 0, 0, 1, 1, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("sub_group", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 1, 1, 0, 0, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("region", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 1, 1, 1, 1, 0, 0])) as ArrayRef,
            ),
            (
                Field::new("event_date", DataType::Date32, false),
                Arc::new(Date32Array::from(vec![
                    18628, 18635, 18620, 18645, 18630, 18625, 18650, 18610,
                ])) as ArrayRef,
            ),
            (
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                Arc::new(BooleanArray::from(vec![
                    true, false, true, true, true, false, true, true,
                ])) as ArrayRef,
            ),
        ];

        let expected_columns = vec![
            (
                Field::new("group_id", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 0, 0, 1, 1, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("sub_group", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 1, 1, 0, 0, 1, 1])) as ArrayRef,
            ),
            (
                Field::new("region", DataType::Int32, false),
                Arc::new(Int32Array::from(vec![0, 0, 1, 1, 1, 1, 0, 0])) as ArrayRef,
            ),
            (
                Field::new("event_date", DataType::Date32, false),
                Arc::new(Date32Array::from(vec![
                    18628, 18635, 18620, 18645, 18630, 18625, 18650, 18610,
                ])) as ArrayRef,
            ),
            (
                Field::new("active_max", DataType::Date32, true),
                Arc::new(Date32Array::from(vec![
                    18628, 18628, 18645, 18645, 18630, 18630, 18650, 18650,
                ])) as ArrayRef,
            ),
            (
                Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                Arc::new(BooleanArray::from(vec![
                    true, false, true, false, true, false, true, false,
                ])) as ArrayRef,
            ),
        ];

        run_aggregate_test(
            &ctx,
            &input_columns,
            &[col("group_id"), col("sub_group"), col("region")],
            &[max(col("event_date")).alias("active_max")],
            &expected_columns,
        )
        .await;
    }
}
