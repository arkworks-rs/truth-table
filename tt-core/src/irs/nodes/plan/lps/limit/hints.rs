use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray},
    compute::{concat, concat_batches},
    record_batch::RecordBatch,
};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::{DataFrame, SessionContext};
use datafusion_common::{Column, DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion_expr::{
    Expr, ExprFunctionExt, FetchType, Limit, SkipType, col, expr::Sort as SortExpr, expr_fn::when,
    lit,
};
use std::sync::Arc;
use tokio::runtime::RuntimeFlavor;

pub(super) fn build_output_dataframe(input: &DataFrame, limit: &Limit) -> DataFrame {
    let input_df = crate::irs::nodes::hints::sort_by_row_id_if_present(input.clone())
        .expect("limit input row-id sort should succeed");

    let skip = match limit.get_skip_type() {
        Ok(SkipType::Literal(skip)) => skip,
        Ok(SkipType::UnsupportedExpr) => {
            panic!("Limit skip must be a literal for proof planning");
        }
        Err(err) => panic!("Limit skip expression error: {err}"),
    };
    let fetch = match limit.get_fetch_type() {
        Ok(FetchType::Literal(fetch)) => fetch,
        Ok(FetchType::UnsupportedExpr) => {
            panic!("Limit fetch must be a literal for proof planning");
        }
        Err(err) => panic!("Limit fetch expression error: {err}"),
    };

    let row_id_sort_exprs: Vec<SortExpr> = input_df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != ROW_ID_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).sort(true, true))
        })
        .collect();
    let has_row_id = !row_id_sort_exprs.is_empty();
    let has_activator = input_df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);

    let df = if has_activator {
        input_df
            .clone()
            .with_column_renamed(ACTIVATOR_COL_NAME, "__activator_orig__")
            .expect("limit should rename activator column")
    } else {
        input_df
            .clone()
            .with_column("__activator_orig__", lit(true))
            .expect("limit should add synthetic activator")
    };

    let mut row_number_builder = row_number().partition_by(vec![col("__activator_orig__")]);
    if has_row_id {
        row_number_builder = row_number_builder.order_by(row_id_sort_exprs);
    }
    let row_number_expr = row_number_builder
        .build()
        .expect("limit row_number window should build")
        .alias("__row_number__");
    let with_row_number = df
        .window(vec![row_number_expr])
        .expect("limit row_number window should apply");

    let start = (skip as i64) + 1;
    let lower = col("__row_number__").gt_eq(lit(start));
    let upper = match fetch {
        Some(fetch) => col("__row_number__").lt_eq(lit((skip + fetch) as i64)),
        None => lit(true),
    };
    let in_range = lower.and(upper);
    let new_activator_expr = when(col("__activator_orig__").and(in_range), lit(true))
        .otherwise(lit(false))
        .expect("limit activator case expression should build");
    let with_new_activator = with_row_number
        .with_column(ACTIVATOR_COL_NAME, new_activator_expr)
        .expect("limit activator update should succeed");

    let trimmed = with_new_activator
        .drop_columns(&["__row_number__", "__activator_orig__"])
        .expect("limit helper columns should be dropped");

    pad_to_power_of_two(trimmed)
}

fn pad_to_power_of_two(df: DataFrame) -> DataFrame {
    pad_to_power_of_two_inner(df).expect("limit output padding should succeed")
}

fn pad_to_power_of_two_inner(df: DataFrame) -> DataFusionResult<DataFrame> {
    let batches = collect_blocking(df.clone())?;
    if batches.is_empty() {
        return pad_empty_df(df);
    }
    let schema_ref = batches[0].schema();
    let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
    let combined = concat_batches(&schema_ref, batch_refs)?;
    let row_count = combined.num_rows();
    let target = row_count.next_power_of_two();
    let pad = target - row_count;
    if pad == 0 {
        return Ok(df);
    }

    let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
    for (idx, field) in schema_ref.fields().iter().enumerate() {
        let base = combined.column(idx).clone();
        let padded = if field.name() == ACTIVATOR_COL_NAME {
            let pad_arr: ArrayRef = Arc::new(BooleanArray::from(vec![false; pad]));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else {
            let last = ScalarValue::try_from_array(base.as_ref(), row_count - 1)?;
            let pad_arr = last.to_array_of_size(pad)?;
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        };
        output_arrays.push(padded);
    }

    let out_batch = RecordBatch::try_new(schema_ref, output_arrays)?;
    let ctx = SessionContext::new();
    ctx.read_batch(out_batch)
}

fn pad_empty_df(df: DataFrame) -> DataFusionResult<DataFrame> {
    let schema_ref = df.schema().as_arrow();
    let target = 1;
    let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
    for field in schema_ref.fields() {
        if field.name() == ACTIVATOR_COL_NAME {
            output_arrays.push(Arc::new(BooleanArray::from(vec![false; target])) as _);
        } else {
            let null = ScalarValue::try_new_null(field.data_type())?;
            output_arrays.push(null.to_array_of_size(target)?);
        }
    }

    let out_batch = RecordBatch::try_new(Arc::new(schema_ref.clone()), output_arrays)?;
    let ctx = SessionContext::new();
    ctx.read_batch(out_batch)
}

fn collect_blocking(df: DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    DataFusionError::Execution("dataframe collection thread panicked".to_string())
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_output_dataframe;
    use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Int32Array, Int64Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use datafusion_common::ScalarValue;
    use datafusion_expr::{Expr, Limit};
    use std::sync::Arc;

    async fn run_limit_test(
        ctx: &SessionContext,
        input_columns: &[(Field, ArrayRef)],
        skip: Option<i64>,
        fetch: Option<i64>,
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

        let skip_expr = skip.map(|val| Expr::Literal(ScalarValue::Int64(Some(val))));
        let fetch_expr = fetch.map(|val| Expr::Literal(ScalarValue::Int64(Some(val))));
        let limit = Limit {
            skip: skip_expr.map(Box::new),
            fetch: fetch_expr.map(Box::new),
            input: Arc::new(input_df.logical_plan().clone()),
        };

        let limited = build_output_dataframe(&input_df, &limit);
        let batches = limited.collect().await.unwrap();

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
    async fn limit_keeps_first_n_active_rows() {
        let ctx = SessionContext::new();
        run_limit_test(
            &ctx,
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![10, 11, 12, 13])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, true, true])),
                ),
            ],
            Some(0),
            Some(2),
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![10, 11, 12, 13])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, false, false])),
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn limit_respects_skip_on_active_rows() {
        let ctx = SessionContext::new();
        run_limit_test(
            &ctx,
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4, 5])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3, 4])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true, false])),
                ),
            ],
            Some(1),
            Some(1),
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 4, 5, 5, 5, 5])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3, 4, 4, 4, 4])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![
                        false, false, true, false, false, false, false, false,
                    ])),
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn limit_allows_unbounded_fetch() {
        let ctx = SessionContext::new();
        run_limit_test(
            &ctx,
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![5, 6, 7, 8])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, false, true])),
                ),
            ],
            Some(1),
            None,
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![5, 6, 7, 8])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![false, true, false, true])),
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn limit_adds_activator_when_missing() {
        let ctx = SessionContext::new();
        run_limit_test(
            &ctx,
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2])),
                ),
            ],
            Some(0),
            Some(2),
            &[
                (
                    Field::new("val", DataType::Int32, false),
                    Arc::new(Int32Array::from(vec![1, 2, 3, 3])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 2])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, false, false])),
                ),
            ],
        )
        .await;
    }
}
