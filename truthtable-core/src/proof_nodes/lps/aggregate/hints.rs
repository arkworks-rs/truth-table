use arithmetic::ACTIVATOR_COL_NAME;
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_expr::{Aggregate, Expr, ExprFunctionExt, JoinType, col, expr_fn::when, lit};
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
    let agg_df = active_df
        .aggregate(aggregate.group_expr.clone(), aggregate.aggr_expr.clone())
        .unwrap();

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
            _ => panic!("Non-column group exprs require a pre-projection step"),
        })
        .collect();

    let group_cols_str: Vec<&str> = group_cols.iter().map(|s| s.as_str()).collect();
    let joined = input
        .clone()
        .join(
            agg_df,
            JoinType::Left,
            &group_cols_str,
            &group_cols_str,
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
    let window_expr = row_number()
        .partition_by(aggregate.group_expr.clone())
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
    with_new_activator
        .drop_columns(&["__row_number__", "__activator_orig__"])
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::build_output_dataframe;
    use arithmetic::ACTIVATOR_COL_NAME;
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Date32Array, Int32Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use datafusion_common::{ScalarValue, TableReference};
    use datafusion_expr::{
        Aggregate, Expr, Operator, col,
        expr::{Alias, BinaryExpr},
    };
    use std::sync::Arc;

    async fn run_projection_test(
        ctx: &SessionContext,
        input_columns: &[(Field, ArrayRef)],
        exprs: &[Expr],
        expected_columns: &[(Field, ArrayRef)],
    ) {
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
        todo!();
        // let projection =
        //     Projection::try_new(exprs.to_vec(), Arc::new(input_df.logical_plan().clone()))
        //         .expect("projection creation should succeed");
        // let projected = build_output_dataframe(&input_df, &projection);
        // let batches = projected.collect().await.unwrap();
        // let expected_schema = Arc::new(Schema::new(
        //     expected_columns
        //         .iter()
        //         .map(|(field, _)| field.clone())
        //         .collect::<Vec<_>>(),
        // ));
        // let expected_batch = RecordBatch::try_new(
        //     expected_schema,
        //     expected_columns
        //         .iter()
        //         .map(|(_, array)| Arc::clone(array))
        //         .collect(),
        // )
        // .expect("expected batch construction should succeed");
        // assert_eq!(batches, vec![expected_batch]);
    }

    #[tokio::test]
    async fn projection_node_output_is_correct() {
        let ctx = SessionContext::new();

        run_projection_test(
            &ctx,
            &[
                (
                    Field::new("val1", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4])),
                ),
                (
                    Field::new("val2", DataType::Date32, false),
                    Arc::new(Date32Array::from(vec![18628, 18629, 18630, 18631])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
            &[Expr::Alias(Alias::new(
                col("val2"),
                None::<TableReference>,
                "projected_val2",
            ))],
            &[
                (
                    Field::new("projected_val2", DataType::Date32, false),
                    Arc::new(Date32Array::from(vec![18628, 18629, 18630, 18631])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
        )
        .await;

        run_projection_test(
            &ctx,
            &[
                (
                    Field::new("val1", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
            &[Expr::Alias(Alias::new(
                Expr::BinaryExpr(BinaryExpr::new(
                    Box::new(col("val1")),
                    Operator::Plus,
                    Box::new(Expr::Literal(ScalarValue::Int64(Some(2)))),
                )),
                None::<TableReference>,
                "val1_plus_two",
            ))],
            &[
                (
                    Field::new("val1_plus_two", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![3, 4, 5, 6])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
        )
        .await;
    }
}
