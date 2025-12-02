use arithmetic::ACTIVATOR_COL_NAME;
use datafusion::prelude::DataFrame;
use datafusion_expr::{Expr, Filter, col};

/// Build a DataFrame that preserves all rows but deactivates ones that do not
/// satisfy the filter predicate by zeroing the activator column.
pub(super) fn build_output_dataframe(input: &DataFrame, filter: &Filter) -> DataFrame {
    let predicate = filter.predicate.clone();
    let projection_exprs: Vec<Expr> = input
        .schema()
        .fields()
        .iter()
        .map(|field| {
            let name = field.name();
            let base_expr = col(name);
            if name == ACTIVATOR_COL_NAME {
                base_expr.and(predicate.clone()).alias(ACTIVATOR_COL_NAME)
            } else {
                base_expr
            }
        })
        .collect();

    input
        .clone()
        .select(projection_exprs)
        .expect("filter application should succeed")
}

#[cfg(test)]
mod tests {
    use super::build_output_dataframe;
    use arithmetic::ACTIVATOR_COL_NAME;
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Int32Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use datafusion_common::ScalarValue;
    use datafusion_expr::{Expr, Filter, col};
    use std::sync::Arc;

    async fn run_filter_test(
        ctx: &SessionContext,
        input_columns: &[(Field, ArrayRef)],
        predicate: Expr,
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
        let filter = Filter::try_new(predicate, Arc::new(input_df.logical_plan().clone()))
            .expect("filter creation should succeed");
        let filtered = build_output_dataframe(&input_df, &filter);
        let batches = filtered.collect().await.unwrap();

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
        assert_eq!(batches, vec![expected_batch]);
    }

    #[tokio::test]
    async fn filter_marks_inactive_rows() {
        let ctx = SessionContext::new();

        run_filter_test(
            &ctx,
            &[
                (
                    Field::new("val1", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, true, true])),
                ),
            ],
            col("val1").gt(Expr::Literal(ScalarValue::Int32(Some(2)))),
            &[
                (
                    Field::new("val1", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![false, false, true, true])),
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn filter_respects_existing_inactive_rows() {
        let ctx = SessionContext::new();

        run_filter_test(
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
            col("val1").gt(Expr::Literal(ScalarValue::Int32(Some(1)))),
            &[
                (
                    Field::new("val1", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![false, false, true, true])),
                ),
            ],
        )
        .await;
    }
}
