use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::{Column, Result as DataFusionResult};
use datafusion_expr::{Expr, ExprFunctionExt, SortExpr, col, lit};

pub fn lex_sort_contiguous(df: DataFrame) -> DataFusionResult<DataFrame> {
    let mut order_by: Vec<SortExpr> = Vec::new();
    let mut projection_exprs: Vec<Expr> = Vec::new();
    let mut row_id_col: Option<Column> = None;
    let mut activator_col: Option<Column> = None;

    for (qualifier, field) in df.schema().iter() {
        let col_ref = Column::new(qualifier.cloned(), field.name());
        if field.name() == ROW_ID_COL_NAME {
            row_id_col = Some(col_ref);
            continue;
        }
        if field.name() == ACTIVATOR_COL_NAME {
            activator_col = Some(col_ref.clone());
        }
        projection_exprs.push(Expr::Column(col_ref));
    }

    if let Some(col_ref) = activator_col {
        order_by.push(Expr::Column(col_ref).sort(false, false));
    }
    for expr in projection_exprs.iter() {
        if matches!(expr, Expr::Column(col) if is_system_column(&col.name)) {
            continue;
        }
        order_by.push(expr.clone().sort(false, false));
    }
    if let Some(col_ref) = row_id_col.clone() {
        order_by.push(Expr::Column(col_ref).sort(true, true));
    }

    let row_number_expr = row_number()
        .partition_by(Vec::new())
        .order_by(order_by.clone())
        .build()?
        .alias("__row_number__");
    projection_exprs.push(row_number_expr);
    let with_row_number = df.select(projection_exprs)?;

    let mut final_exprs: Vec<Expr> = with_row_number
        .schema()
        .fields()
        .iter()
        .filter_map(|field| (field.name() != "__row_number__").then_some(col(field.name())))
        .collect();
    final_exprs.push((col("__row_number__") - lit(1_i64)).alias(ROW_ID_COL_NAME));
    let with_row_id = with_row_number.select(final_exprs)?;
    let mut final_order_by: Vec<SortExpr> = Vec::new();
    let schema = with_row_id.schema();
    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME)
    {
        let activator_expr = schema
            .iter()
            .find_map(|(qualifier, field)| {
                (field.name() == ACTIVATOR_COL_NAME).then(|| {
                    Expr::Column(Column::new(qualifier.cloned(), field.name()))
                        .sort(false, false)
                })
            })
            .expect("activator column should exist");
        final_order_by.push(activator_expr);
    }
    for (qualifier, field) in schema.iter() {
        if is_system_column(field.name()) {
            continue;
        }
        final_order_by.push(
            Expr::Column(Column::new(qualifier.cloned(), field.name())).sort(false, false),
        );
    }
    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        let row_id_expr = schema
            .iter()
            .find_map(|(qualifier, field)| {
                (field.name() == ROW_ID_COL_NAME).then(|| {
                    Expr::Column(Column::new(qualifier.cloned(), field.name()))
                        .sort(true, true)
                })
            })
            .expect("row id column should exist");
        final_order_by.push(row_id_expr);
    }
    with_row_id.sort(final_order_by)
}

#[cfg(test)]
mod tests {
    use super::lex_sort_contiguous;
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Int64Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use std::sync::Arc;

    fn build_df(schema: Schema, columns: Vec<ArrayRef>) -> datafusion::prelude::DataFrame {
        let batch = RecordBatch::try_new(Arc::new(schema), columns).expect("record batch");
        let ctx = SessionContext::new();
        ctx.read_batch(batch).expect("dataframe")
    }

    fn collect_single_batch(df: datafusion::prelude::DataFrame) -> RecordBatch {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let batches = rt.block_on(df.collect()).expect("collect");
        assert_eq!(batches.len(), 1, "expected single batch");
        batches[0].clone()
    }

    fn int64_column(batch: &RecordBatch, name: &str) -> Vec<i64> {
        let array = batch
            .column(batch.schema().index_of(name).expect("column"))
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("int64 column");
        (0..array.len()).map(|i| array.value(i)).collect()
    }

    fn bool_column(batch: &RecordBatch, name: &str) -> Vec<bool> {
        let array = batch
            .column(batch.schema().index_of(name).expect("column"))
            .as_any()
            .downcast_ref::<BooleanArray>()
            .expect("bool column");
        (0..array.len()).map(|i| array.value(i)).collect()
    }

    #[test]
    fn lex_sort_contiguous_moves_active_rows_first() {
        // Input: mixed activator flags and keys; output should place active rows first and
        // reassign row ids to 0..n-1 in that new order.
        let schema = Schema::new(vec![
            Field::new("k1", DataType::Int64, false),
            Field::new("k2", DataType::Int64, false),
            Field::new("__activator__", DataType::Boolean, false),
            Field::new("__row_id__", DataType::Int64, false),
        ]);
        let df = build_df(
            schema,
            vec![
                Arc::new(Int64Array::from(vec![2, 1, 2, 1])) as ArrayRef,
                Arc::new(Int64Array::from(vec![5, 4, 5, 3])) as ArrayRef,
                Arc::new(BooleanArray::from(vec![false, true, true, false])) as ArrayRef,
                Arc::new(Int64Array::from(vec![10, 11, 12, 13])) as ArrayRef,
            ],
        );

        let sorted = lex_sort_contiguous(df).expect("lex sort");
        let batch = collect_single_batch(sorted);

        assert_eq!(
            bool_column(&batch, "__activator__"),
            vec![true, true, false, false]
        );
        assert_eq!(int64_column(&batch, "__row_id__"), vec![0, 1, 2, 3]);
    }

    #[test]
    fn lex_sort_contiguous_uses_row_id_for_ties() {
        // Input: all rows identical on sort keys; output order should follow original row_id,
        // then row_id is rewritten to 0..n-1 while keys stay unchanged.
        let schema = Schema::new(vec![
            Field::new("k1", DataType::Int64, false),
            Field::new("__activator__", DataType::Boolean, false),
            Field::new("__row_id__", DataType::Int64, false),
        ]);
        let df = build_df(
            schema,
            vec![
                Arc::new(Int64Array::from(vec![7, 7, 7, 7])) as ArrayRef,
                Arc::new(BooleanArray::from(vec![true, true, true, true])) as ArrayRef,
                Arc::new(Int64Array::from(vec![3, 1, 4, 2])) as ArrayRef,
            ],
        );

        let sorted = lex_sort_contiguous(df).expect("lex sort");
        let batch = collect_single_batch(sorted);

        assert_eq!(int64_column(&batch, "__row_id__"), vec![0, 1, 2, 3]);
        assert_eq!(int64_column(&batch, "k1"), vec![7, 7, 7, 7]);
    }

    #[test]
    fn lex_sort_contiguous_without_row_id() {
        // Input: no row_id column; output sorts by activator then key, and synthesizes row_id.
        let schema = Schema::new(vec![
            Field::new("k1", DataType::Int64, false),
            Field::new("__activator__", DataType::Boolean, false),
        ]);
        let df = build_df(
            schema,
            vec![
                Arc::new(Int64Array::from(vec![3, 1, 2])) as ArrayRef,
                Arc::new(BooleanArray::from(vec![false, true, true])) as ArrayRef,
            ],
        );

        let sorted = lex_sort_contiguous(df).expect("lex sort");
        let batch = collect_single_batch(sorted);

        assert_eq!(
            bool_column(&batch, "__activator__"),
            vec![true, true, false]
        );
        assert_eq!(int64_column(&batch, "k1"), vec![2, 1, 3]);
        assert_eq!(int64_column(&batch, "__row_id__"), vec![0, 1, 2]);
    }
}
