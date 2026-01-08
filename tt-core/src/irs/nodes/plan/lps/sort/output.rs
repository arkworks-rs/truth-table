use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::prelude::DataFrame;
use datafusion_expr::{Sort, col, expr::Sort as SortExpr};

/// Sorts by activator first (active rows first), then the provided sort
/// expressions, and finally `__row_id__` when present for deterministic output.
pub(crate) fn sort_df(input: &DataFrame, sort: &Sort) -> DataFrame {
    // Prefix sort with activator so active rows come first.
    let mut sort_exprs: Vec<SortExpr> = Vec::with_capacity(sort.expr.len() + 2);
    sort_exprs.push(col(ACTIVATOR_COL_NAME).sort(false, false));
    // Apply the sort expressions requested by the query.
    sort_exprs.extend(sort.expr.clone());
    if input
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        // Stabilize ordering for identical sort keys.
        sort_exprs.push(col(ROW_ID_COL_NAME).sort(true, true));
    }

    input
        .clone()
        .sort(sort_exprs)
        .expect("sorting activated rows should succeed")
}

#[cfg(test)]
mod tests {
    use super::sort_df;
    use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Int32Array, Int64Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use datafusion_expr::{LogicalPlan, Sort, col, expr::Sort as SortExpr};
    use std::sync::Arc;

    async fn run_sort_test(
        ctx: &SessionContext,
        input_columns: &[(Field, ArrayRef)],
        sort_exprs: Vec<SortExpr>,
        expected_columns: &[(Field, ArrayRef)],
    ) {
        // Build input DataFrame from provided columns (each entry is a full column).
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
        .expect("input batch");
        let input_df = ctx
            .read_batch(input_batch)
            .expect("failed to read batch into DataFrame");

        // Apply sorting with provided expressions (activator-first is injected inside sort_df).
        let sort = Sort {
            expr: sort_exprs,
            input: Arc::new(LogicalPlan::from(input_df.logical_plan().clone())),
            fetch: None,
        };

        let sorted_df = sort_df(&input_df, &sort);
        let batches = sorted_df.collect().await.unwrap();

        // Build expected batch for comparison (expected columns listed in final row order after sorting).
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
        .expect("expected batch");

        assert_eq!(batches, vec![expected_batch]);
    }

    #[tokio::test]
    async fn sort_active_rows_first() {
        let ctx = SessionContext::new();
        // Input: val=[3,1,4,2], activator=[F,T,F,T]; sort by val asc with actives first.
        // Output should be val=[1,2,3,4], activator=[T,T,F,F].
        run_sort_test(
            &ctx,
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![3, 1, 4, 2])) as ArrayRef,
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![false, true, false, true])) as ArrayRef,
                ),
            ],
            vec![col("val").sort(true, true)],
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4])) as ArrayRef,
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, false, false])) as ArrayRef,
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn sort_active_rows_then_by_value_desc() {
        let ctx = SessionContext::new();
        // Input: val=[10,5,7,2], activator=[F,T,T,F]; sort by val desc with actives first.
        // Output should be val=[7,5,10,2], activator=[T,T,F,F].
        run_sort_test(
            &ctx,
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![10, 5, 7, 2])) as ArrayRef,
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![false, true, true, false])) as ArrayRef,
                ),
            ],
            vec![col("val").sort(false, true)],
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![7, 5, 10, 2])) as ArrayRef,
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, false, false])) as ArrayRef,
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn sort_active_rows_then_two_columns() {
        let ctx = SessionContext::new();
        // Input: col_a=[1,2,1,2,3], col_b=[9,8,7,6,5], activator=[T,F,T,F,T];
        // Sort keys: activator desc (implicit), then col_a asc, then col_b desc.
        // Output should be col_a=[1,1,3,2,2], col_b=[9,7,5,8,6], activator=[T,T,T,F,F].
        run_sort_test(
            &ctx,
            &[
                (
                    Field::new("col_a", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 1, 2, 3])) as ArrayRef,
                ),
                (
                    Field::new("col_b", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![9, 8, 7, 6, 5])) as ArrayRef,
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, false, true])) as ArrayRef,
                ),
            ],
            vec![
                col("col_a").sort(true, true),
                col("col_b").sort(false, true),
            ],
            &[
                (
                    Field::new("col_a", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 1, 3, 2, 2])) as ArrayRef,
                ),
                (
                    Field::new("col_b", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![9, 7, 5, 8, 6])) as ArrayRef,
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, true, false, false])) as ArrayRef,
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn sort_uses_row_id_to_break_ties() {
        let ctx = SessionContext::new();
        // Input: val=[1,1,1], tag=[20,0,10], activator=[T,T,T], row_id=[2,0,1].
        // All sort keys equal, so row_id should determine final order: row_id=[0,1,2].
        run_sort_test(
            &ctx,
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 1, 1])) as ArrayRef,
                ),
                (
                    Field::new("tag", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![20, 0, 10])) as ArrayRef,
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, true])) as ArrayRef,
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![2, 0, 1])) as ArrayRef,
                ),
            ],
            vec![col("val").sort(true, true)],
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 1, 1])) as ArrayRef,
                ),
                (
                    Field::new("tag", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![0, 10, 20])) as ArrayRef,
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, true])) as ArrayRef,
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2])) as ArrayRef,
                ),
            ],
        )
        .await;
    }
}
