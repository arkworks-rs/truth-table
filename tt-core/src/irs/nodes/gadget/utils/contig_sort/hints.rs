use crate::irs::nodes::gadget::utils::contig_sort::{
    DIFF_INPUT_LABEL, ROTATED_INPUT_LABEL, TIE_INDICATOR_LABEL, diff_output_type,
};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use datafusion::arrow::{
    array::{
        Array, ArrayRef, BooleanArray, Date32Array, Float32Array, Float64Array, Int8Array,
        Int16Array, Int32Array, Int64Array, new_null_array,
    },
    compute::{concat, concat_batches},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::logical_expr::Expr;
use datafusion::logical_expr::col;
use datafusion::logical_expr::lit;
use datafusion::prelude::DataFrame;
use datafusion::prelude::SessionContext;
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion_expr::ExprFunctionExt;
use datafusion_expr::SortExpr;
use datafusion_expr::when;
use datafusion_expr::{Cast, Operator, expr::BinaryExpr};

use datafusion::functions_window::expr_fn::{first_value, lead};
use indexmap::IndexMap;
pub(crate) fn populate_rotated(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
    skip_collection: bool,
) {
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    let rotated_df = rotate(input_hint.data_frame().clone(), order_by, skip_collection)
        .expect("sort rotate planning should succeed");
    let should_materialize = rotated_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    let rotated_hint = crate::irs::nodes::hints::HintDF::new(rotated_df, should_materialize);
    gadget_payload.insert(ROTATED_INPUT_LABEL.to_string(), rotated_hint);
}

pub(crate) fn populate_tie_indicator(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) {
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    let tie_df = tie_indicator(input_hint.data_frame().clone(), order_by, sort_specs)
        .expect("sort tie indicator planning should succeed");
    let should_materialize = tie_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    let tie_hint = crate::irs::nodes::hints::HintDF::new(tie_df, should_materialize);
    gadget_payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_hint);
}

pub(crate) fn populate_diff(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) {
    // Materialize per-column diffs so sign checks see in-range values.
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    let diff_df = diff_input(input_hint.data_frame().clone(), order_by, sort_specs)
        .expect("sort diff planning should succeed");
    let should_materialize = diff_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    let diff_hint = crate::irs::nodes::hints::HintDF::new(diff_df, should_materialize);
    gadget_payload.insert(DIFF_INPUT_LABEL.to_string(), diff_hint);
}

pub(crate) fn populate_tie_and_diff(
    gadget_payload: &mut IndexMap<String, crate::irs::nodes::hints::HintDF>,
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) {
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    let ordered = input_hint
        .data_frame()
        .clone()
        .sort(order_by.clone())
        .expect("sort ordering for tie/diff planning should succeed");

    let tie_df = tie_indicator_on_ordered(ordered.clone(), order_by.clone(), sort_specs)
        .expect("sort tie indicator planning should succeed");
    let tie_should_materialize = tie_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    let tie_hint = crate::irs::nodes::hints::HintDF::new(tie_df, tie_should_materialize);
    gadget_payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_hint);

    let diff_df = diff_input_on_ordered(ordered, order_by, sort_specs)
        .expect("sort diff planning should succeed");
    let diff_should_materialize = diff_df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), field.name() != ROW_ID_COL_NAME))
        .collect();
    let diff_hint = crate::irs::nodes::hints::HintDF::new(diff_df, diff_should_materialize);
    gadget_payload.insert(DIFF_INPUT_LABEL.to_string(), diff_hint);
}

pub(crate) fn sort_input_for_contig_sort(
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    input_hint.data_frame().clone().sort(order_by)
}

pub(crate) fn rotate(
    df: DataFrame,
    order_by: Vec<SortExpr>,
    skip_collection: bool,
) -> DataFusionResult<DataFrame> {
    if skip_collection {
        // Verifier planning should not collect or materialize data.
        // Keep only the non-row-id columns with the same schema shape expected by
        // the downstream gadgets.
        let projected: Vec<Expr> = df
            .schema()
            .fields()
            .iter()
            .filter_map(|field| (field.name() != ROW_ID_COL_NAME).then_some(col(field.name())))
            .collect();
        return df.select(projected);
    }

    // Important: we rotate *after* power-of-two padding.
    // If rotation happens first, the wrap row gets buried by appended rows and the
    // prescribed permutation no longer matches the intended cyclic shift.
    let ordered = if order_by.is_empty() {
        let has_row_id = df
            .schema()
            .fields()
            .iter()
            .any(|field| field.name() == ROW_ID_COL_NAME);
        if !has_row_id {
            return Err(DataFusionError::Plan(format!(
                "rotate requires {} column for deterministic ordering",
                ROW_ID_COL_NAME
            )));
        }
        df.sort(vec![col(ROW_ID_COL_NAME).sort(true, true)])?
    } else {
        df.sort(order_by)?
    };
    // Collect to Arrow so we can deterministically pad and then perform an explicit
    // cyclic array rotation (DataFusion window + post-padding was the source of mismatch).
    let batches = collect_blocking(ordered, skip_collection)?;
    if batches.is_empty() {
        return Err(DataFusionError::Execution(
            "rotate input produced no batches".to_string(),
        ));
    }

    let schema_ref = batches[0].schema();
    let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
    let combined = concat_batches(&schema_ref, batch_refs)?;
    let padded = pad_batch_to_power_of_two_with_zeros(&combined)?;
    let row_count = padded.num_rows();

    let mut out_fields = Vec::new();
    let mut out_cols = Vec::new();
    for (idx, field) in padded.schema().fields().iter().enumerate() {
        if field.name() == ROW_ID_COL_NAME {
            continue;
        }
        let source = padded.column(idx).clone();
        let rotated = if row_count <= 1 {
            source
        } else {
            let tail = source.slice(1, row_count - 1);
            let head = source.slice(0, 1);
            concat(&[tail.as_ref(), head.as_ref()])?
        };
        out_fields.push(field.as_ref().clone());
        out_cols.push(rotated);
    }

    let out_schema = std::sync::Arc::new(datafusion::arrow::datatypes::Schema::new_with_metadata(
        out_fields,
        padded.schema().metadata().clone(),
    ));
    let out_batch = RecordBatch::try_new(out_schema, out_cols)?;
    SessionContext::new().read_batch(out_batch)
}

fn collect_blocking(
    df: DataFrame,
    skip_collection: bool,
) -> datafusion_common::Result<Vec<RecordBatch>> {
    if skip_collection {
        return Err(DataFusionError::Execution(
            "verifier planning must not collect DataFrames".to_string(),
        ));
    }
    // This helper is used from both async and sync call paths; avoid creating nested
    // runtimes in multithread contexts and keep behavior consistent in tests.
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            tokio::runtime::RuntimeFlavor::CurrentThread => {
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

fn pad_batch_to_power_of_two_with_zeros(batch: &RecordBatch) -> DataFusionResult<RecordBatch> {
    let row_count = batch.num_rows();
    let target = if row_count == 0 {
        2
    } else {
        row_count.next_power_of_two()
    };
    let pad = target - row_count;
    if pad == 0 {
        return Ok(batch.clone());
    }

    let mut out_cols = Vec::with_capacity(batch.num_columns());
    for (idx, field) in batch.schema().fields().iter().enumerate() {
        let base = batch.column(idx).clone();
        let pad_arr: ArrayRef = if field.name() == ACTIVATOR_COL_NAME {
            // Newly padded rows are always inactive.
            std::sync::Arc::new(BooleanArray::from(vec![false; pad]))
        } else if field.name() == ROW_ID_COL_NAME {
            // Keep row ids contiguous so downstream deterministic ordering by row id remains valid.
            let start = if row_count > 0 {
                ScalarValue::try_from_array(base.as_ref(), row_count - 1)
                    .ok()
                    .and_then(|v| match v {
                        ScalarValue::Int64(Some(x)) => Some(x + 1),
                        ScalarValue::UInt64(Some(x)) => i64::try_from(x).ok().map(|x| x + 1),
                        _ => None,
                    })
                    .unwrap_or(0)
            } else {
                0
            };
            let vals: Vec<i64> = (0..pad as i64).map(|off| start + off).collect();
            std::sync::Arc::new(Int64Array::from(vals))
        } else {
            // Data columns are zero-filled for padded rows, matching gadget assumptions.
            zero_array(field.data_type(), pad)?
        };
        out_cols.push(concat(&[base.as_ref(), pad_arr.as_ref()])?);
    }

    RecordBatch::try_new(batch.schema(), out_cols).map_err(Into::into)
}

fn zero_array(data_type: &DataType, len: usize) -> DataFusionResult<ArrayRef> {
    let scalar = match data_type {
        DataType::Boolean => Some(ScalarValue::Boolean(Some(false))),
        DataType::Int8 => Some(ScalarValue::Int8(Some(0))),
        DataType::Int16 => Some(ScalarValue::Int16(Some(0))),
        DataType::Int32 => Some(ScalarValue::Int32(Some(0))),
        DataType::Int64 => Some(ScalarValue::Int64(Some(0))),
        DataType::UInt8 => Some(ScalarValue::UInt8(Some(0))),
        DataType::UInt16 => Some(ScalarValue::UInt16(Some(0))),
        DataType::UInt32 => Some(ScalarValue::UInt32(Some(0))),
        DataType::UInt64 => Some(ScalarValue::UInt64(Some(0))),
        DataType::Float32 => Some(ScalarValue::Float32(Some(0.0))),
        DataType::Float64 => Some(ScalarValue::Float64(Some(0.0))),
        DataType::Date32 => Some(ScalarValue::Date32(Some(0))),
        DataType::Date64 => Some(ScalarValue::Date64(Some(0))),
        DataType::Timestamp(unit, tz) => match unit {
            datafusion::arrow::datatypes::TimeUnit::Second => {
                Some(ScalarValue::TimestampSecond(Some(0), tz.clone()))
            }
            datafusion::arrow::datatypes::TimeUnit::Millisecond => {
                Some(ScalarValue::TimestampMillisecond(Some(0), tz.clone()))
            }
            datafusion::arrow::datatypes::TimeUnit::Microsecond => {
                Some(ScalarValue::TimestampMicrosecond(Some(0), tz.clone()))
            }
            datafusion::arrow::datatypes::TimeUnit::Nanosecond => {
                Some(ScalarValue::TimestampNanosecond(Some(0), tz.clone()))
            }
        },
        DataType::Decimal128(precision, scale) => {
            Some(ScalarValue::Decimal128(Some(0), *precision, *scale))
        }
        _ => None,
    };

    if let Some(scalar) = scalar {
        scalar.to_array_of_size(len)} else {
        Ok(new_null_array(data_type, len))
    }
}

pub(crate) fn diff_input(
    df: DataFrame,
    order_by: Vec<SortExpr>,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let schema = df.schema();
    let has_row_id = schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let order_by = if !order_by.is_empty() {
        order_by
    } else if has_row_id {
        vec![col(ROW_ID_COL_NAME).sort(true, true)]
    } else {
        return Err(DataFusionError::Plan(format!(
            "diff_input requires {} column for deterministic ordering",
            ROW_ID_COL_NAME
        )));
    };

    let ordered = df.sort(order_by.clone())?;
    diff_input_on_ordered(ordered, order_by, sort_specs)
}

fn diff_input_on_ordered(
    ordered: DataFrame,
    order_by: Vec<SortExpr>,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    if has_only_explicit_diff_types(&ordered)? {
        return diff_input_on_ordered_explicit(ordered, sort_specs);
    }

    diff_input_on_ordered_via_windows(ordered, order_by, sort_specs)
}

fn diff_input_on_ordered_via_windows(
    ordered: DataFrame,
    order_by: Vec<SortExpr>,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let mut diff_cols = Vec::new();

    for field in ordered.schema().fields() {
        let name = field.name();
        if is_system_column(name) {
            continue;
        }
        let lead_expr = lead(col(name), Some(1), None)
            .order_by(order_by.clone())
            .build()?;
        let first_expr = first_value(col(name)).order_by(order_by.clone()).build()?;
        let rotated_expr = when(lead_expr.clone().is_null(), first_expr).otherwise(lead_expr)?;
        let is_asc = sort_is_asc(sort_specs, name);
        // Date32 subtraction yields a duration, so cast to Int32 before subtracting.
        let diff_expr = if field.data_type() == &datafusion::arrow::datatypes::DataType::Date32 {
            let lhs = Expr::Cast(Cast {
                expr: Box::new(if is_asc {
                    rotated_expr.clone()
                } else {
                    col(name)
                }),
                data_type: datafusion::arrow::datatypes::DataType::Int32,
            });
            let rhs = Expr::Cast(Cast {
                expr: Box::new(if is_asc {
                    col(name)
                } else {
                    rotated_expr.clone()
                }),
                data_type: datafusion::arrow::datatypes::DataType::Int32,
            });
            Expr::BinaryExpr(BinaryExpr {
                left: Box::new(lhs),
                op: Operator::Minus,
                right: Box::new(rhs),
            })
            .alias(name.to_string())
        } else if is_numeric_type(field.data_type()) {
            let raw_diff = if is_asc {
                Expr::BinaryExpr(BinaryExpr {
                    left: Box::new(rotated_expr.clone()),
                    op: Operator::Minus,
                    right: Box::new(col(name)),
                })
            } else {
                Expr::BinaryExpr(BinaryExpr {
                    left: Box::new(col(name)),
                    op: Operator::Minus,
                    right: Box::new(rotated_expr.clone()),
                })
            };
            Expr::Cast(Cast {
                expr: Box::new(raw_diff),
                data_type: field.data_type().clone(),
            })
            .alias(name.to_string())
        } else {
            // For non-numeric types, emit a sign-only diff via comparisons.
            let (left, right) = if is_asc {
                (rotated_expr.clone(), col(name))
            } else {
                (col(name), rotated_expr.clone())
            };
            when(left.clone().gt(right.clone()), lit(1_i64))
                .when(left.lt(right), lit(-1_i64))
                .otherwise(lit(0_i64))?
                .alias(name.to_string())
        };
        diff_cols.push(diff_expr);
    }

    ordered.select(diff_cols)
}

fn diff_input_on_ordered_explicit(
    ordered: DataFrame,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let batches = collect_blocking(ordered, false)?;
    if batches.is_empty() {
        return Err(DataFusionError::Execution(
            "diff_input_on_ordered produced no batches".to_string(),
        ));
    }

    let schema_ref = batches[0].schema();
    let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
    let combined = concat_batches(&schema_ref, batch_refs)?;
    let row_count = combined.num_rows();

    let mut out_fields = Vec::new();
    let mut out_cols = Vec::new();
    for (idx, field) in combined.schema().fields().iter().enumerate() {
        let name = field.name();
        if is_system_column(name) {
            continue;
        }

        let source = combined.column(idx).clone();
        let rotated = rotate_array(source.clone(), row_count)?;
        let is_asc = sort_is_asc(sort_specs, name);
        let (lhs, rhs) = if is_asc {
            (rotated.as_ref(), source.as_ref())
        } else {
            (source.as_ref(), rotated.as_ref())
        };
        let diff_col = materialize_diff_array(field.data_type(), lhs, rhs)?;
        out_fields.push(Field::new(
            name,
            diff_output_type(field.data_type()),
            field.is_nullable(),
        ));
        out_cols.push(diff_col);
    }

    let out_schema = std::sync::Arc::new(Schema::new_with_metadata(
        out_fields,
        combined.schema().metadata().clone(),
    ));
    let out_batch = RecordBatch::try_new(out_schema, out_cols)?;
    SessionContext::new().read_batch(out_batch)
}

fn rotate_array(source: ArrayRef, row_count: usize) -> DataFusionResult<ArrayRef> {
    if row_count <= 1 {
        return Ok(source);
    }
    let tail = source.slice(1, row_count - 1);
    let head = source.slice(0, 1);
    concat(&[tail.as_ref(), head.as_ref()]).map_err(Into::into)
}

fn has_only_explicit_diff_types(df: &DataFrame) -> DataFusionResult<bool> {
    Ok(df
        .schema()
        .fields()
        .iter()
        .filter(|field| !is_system_column(field.name()))
        .all(|field| is_explicit_diff_type(field.data_type())))
}

fn is_explicit_diff_type(data_type: &DataType) -> bool {
    matches!(
        data_type,
        DataType::Int8
            | DataType::Int16
            | DataType::Int32
            | DataType::Int64
            | DataType::Float32
            | DataType::Float64
            | DataType::Date32
    )
}

fn materialize_diff_array(
    data_type: &DataType,
    lhs: &dyn Array,
    rhs: &dyn Array,
) -> DataFusionResult<ArrayRef> {
    match data_type {
        DataType::Int8 => diff_int8_array(lhs, rhs),
        DataType::Int16 => diff_int16_array(lhs, rhs),
        DataType::Int32 => diff_int32_array(lhs, rhs),
        DataType::Int64 => diff_int64_array(lhs, rhs),
        DataType::Float32 => diff_float32_array(lhs, rhs),
        DataType::Float64 => diff_float64_array(lhs, rhs),
        DataType::Date32 => diff_date32_array(lhs, rhs),
        _ => sign_only_diff_array(lhs, rhs),
    }
}

fn diff_int8_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let lhs = lhs
        .as_any()
        .downcast_ref::<Int8Array>()
        .ok_or_else(|| DataFusionError::Execution("diff lhs Int8 mismatch".to_string()))?;
    let rhs = rhs
        .as_any()
        .downcast_ref::<Int8Array>()
        .ok_or_else(|| DataFusionError::Execution("diff rhs Int8 mismatch".to_string()))?;
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                None
            } else {
                Some(lhs.value(idx) - rhs.value(idx))
            }
        })
        .collect::<Vec<_>>();
    Ok(std::sync::Arc::new(Int8Array::from(values)))
}

fn diff_int16_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let lhs = lhs
        .as_any()
        .downcast_ref::<Int16Array>()
        .ok_or_else(|| DataFusionError::Execution("diff lhs Int16 mismatch".to_string()))?;
    let rhs = rhs
        .as_any()
        .downcast_ref::<Int16Array>()
        .ok_or_else(|| DataFusionError::Execution("diff rhs Int16 mismatch".to_string()))?;
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                None
            } else {
                Some(lhs.value(idx) - rhs.value(idx))
            }
        })
        .collect::<Vec<_>>();
    Ok(std::sync::Arc::new(Int16Array::from(values)))
}

fn diff_int32_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let lhs = lhs
        .as_any()
        .downcast_ref::<Int32Array>()
        .ok_or_else(|| DataFusionError::Execution("diff lhs Int32 mismatch".to_string()))?;
    let rhs = rhs
        .as_any()
        .downcast_ref::<Int32Array>()
        .ok_or_else(|| DataFusionError::Execution("diff rhs Int32 mismatch".to_string()))?;
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                None
            } else {
                Some(lhs.value(idx) - rhs.value(idx))
            }
        })
        .collect::<Vec<_>>();
    Ok(std::sync::Arc::new(Int32Array::from(values)))
}

fn diff_int64_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let lhs = lhs
        .as_any()
        .downcast_ref::<Int64Array>()
        .ok_or_else(|| DataFusionError::Execution("diff lhs Int64 mismatch".to_string()))?;
    let rhs = rhs
        .as_any()
        .downcast_ref::<Int64Array>()
        .ok_or_else(|| DataFusionError::Execution("diff rhs Int64 mismatch".to_string()))?;
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                None
            } else {
                Some(lhs.value(idx) - rhs.value(idx))
            }
        })
        .collect::<Vec<_>>();
    Ok(std::sync::Arc::new(Int64Array::from(values)))
}

fn diff_float32_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let lhs = lhs
        .as_any()
        .downcast_ref::<Float32Array>()
        .ok_or_else(|| DataFusionError::Execution("diff lhs Float32 mismatch".to_string()))?;
    let rhs = rhs
        .as_any()
        .downcast_ref::<Float32Array>()
        .ok_or_else(|| DataFusionError::Execution("diff rhs Float32 mismatch".to_string()))?;
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                None
            } else {
                Some(lhs.value(idx) - rhs.value(idx))
            }
        })
        .collect::<Vec<_>>();
    Ok(std::sync::Arc::new(Float32Array::from(values)))
}

fn diff_float64_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let lhs = lhs
        .as_any()
        .downcast_ref::<Float64Array>()
        .ok_or_else(|| DataFusionError::Execution("diff lhs Float64 mismatch".to_string()))?;
    let rhs = rhs
        .as_any()
        .downcast_ref::<Float64Array>()
        .ok_or_else(|| DataFusionError::Execution("diff rhs Float64 mismatch".to_string()))?;
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                None
            } else {
                Some(lhs.value(idx) - rhs.value(idx))
            }
        })
        .collect::<Vec<_>>();
    Ok(std::sync::Arc::new(Float64Array::from(values)))
}

fn diff_date32_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let lhs = lhs
        .as_any()
        .downcast_ref::<Date32Array>()
        .ok_or_else(|| DataFusionError::Execution("diff lhs Date32 mismatch".to_string()))?;
    let rhs = rhs
        .as_any()
        .downcast_ref::<Date32Array>()
        .ok_or_else(|| DataFusionError::Execution("diff rhs Date32 mismatch".to_string()))?;
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                None
            } else {
                Some(lhs.value(idx) - rhs.value(idx))
            }
        })
        .collect::<Vec<_>>();
    Ok(std::sync::Arc::new(Int32Array::from(values)))
}

fn sign_only_diff_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                Ok(None)
            } else {
                let left = ScalarValue::try_from_array(lhs, idx)?;
                let right = ScalarValue::try_from_array(rhs, idx)?;
                let sign = match left.partial_cmp(&right) {
                    Some(std::cmp::Ordering::Greater) => 1_i64,
                    Some(std::cmp::Ordering::Less) => -1_i64,
                    _ => 0_i64,
                };
                Ok(Some(sign))
            }
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    Ok(std::sync::Arc::new(Int64Array::from(values)))
}

// Keep diff materialization on numeric types to avoid invalid arithmetic in DataFusion.
fn is_numeric_type(data_type: &datafusion::arrow::datatypes::DataType) -> bool {
    use datafusion::arrow::datatypes::DataType;
    matches!(
        data_type,
        DataType::Int8
            | DataType::Int16
            | DataType::Int32
            | DataType::Int64
            | DataType::UInt8
            | DataType::UInt16
            | DataType::UInt32
            | DataType::UInt64
            | DataType::Float16
            | DataType::Float32
            | DataType::Float64
            | DataType::Decimal128(_, _)
            | DataType::Decimal256(_, _)
    )
}

/// Builds a boolean tie-indicator table:
/// `tie_k` is true on row i iff rows i and i+1 match on columns [0..k-1].
pub(crate) fn tie_indicator(
    df: DataFrame,
    order_by: Vec<SortExpr>,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let schema = df.schema();
    let has_row_id = schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let order_by = if !order_by.is_empty() {
        order_by
    } else if has_row_id {
        vec![col(ROW_ID_COL_NAME).sort(true, true)]
    } else {
        return Err(DataFusionError::Plan(
            "tie_indicator requires ordering or __row_id__ column".to_string(),
        ));
    };

    let mut data_cols: Vec<String> = schema
        .fields()
        .iter()
        .map(|field| field.name().to_string())
        // Tie indicators should only consider data columns (not activator/row_id).
        .filter(|name| !is_system_column(name))
        .collect();
    if !sort_specs.is_empty() {
        let mut ordered = Vec::with_capacity(data_cols.len());
        for (name, _, _) in sort_specs {
            let normalized = normalize_sort_name(name);
            if let Some(col_name) = data_cols
                .iter()
                .find(|col_name| normalize_sort_name(col_name) == normalized)
            {
                ordered.push(col_name.clone());
            }
        }
        if ordered.len() == data_cols.len() {
            data_cols = ordered;
        }
    }
    let ordered = df.sort(order_by.clone())?;
    tie_indicator_on_ordered(ordered, order_by, sort_specs)
}

fn tie_indicator_on_ordered(
    ordered: DataFrame,
    order_by: Vec<SortExpr>,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let mut data_cols: Vec<String> = ordered
        .schema()
        .fields()
        .iter()
        .map(|field| field.name().to_string())
        .filter(|name| !is_system_column(name))
        .collect();
    if !sort_specs.is_empty() {
        let mut ordered_cols = Vec::with_capacity(data_cols.len());
        for (name, _, _) in sort_specs {
            let normalized = normalize_sort_name(name);
            if let Some(col_name) = data_cols
                .iter()
                .find(|col_name| normalize_sort_name(col_name) == normalized)
            {
                ordered_cols.push(col_name.clone());
            }
        }
        if ordered_cols.len() == data_cols.len() {
            data_cols = ordered_cols;
        }
    }
    if data_cols.is_empty() {
        return ordered.select(Vec::<Expr>::new());
    }
    // Materialize ties from the already sorted batch so the tie rows are aligned
    // with the same physical row order consumed by TABLE/ROTATED/DIFF.
    let ordered = if order_by.is_empty() {
        ordered
    } else {
        ordered.sort(order_by)?
    };
    let batches = collect_blocking(ordered, false)?;
    if batches.is_empty() {
        return Err(DataFusionError::Execution(
            "tie input produced no batches".to_string(),
        ));
    }
    let schema_ref = batches[0].schema();
    let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
    let combined = concat_batches(&schema_ref, batch_refs)?;
    let row_count = combined.num_rows();

    let data_arrays = data_cols
        .iter()
        .map(|col_name| {
            combined
                .schema()
                .index_of(col_name)
                .map(|idx| combined.column(idx).clone())
                .map_err(Into::into)
        })
        .collect::<DataFusionResult<Vec<_>>>()?;

    if data_cols.len() == 1 {
        let values = (0..row_count)
            .map(|row_idx| row_idx + 1 < row_count)
            .collect::<Vec<_>>();
        let out_schema = std::sync::Arc::new(Schema::new(vec![Field::new(
            "tie_0",
            DataType::Boolean,
            false,
        )]));
        let out_batch = RecordBatch::try_new(
            out_schema,
            vec![std::sync::Arc::new(BooleanArray::from(values))],
        )?;
        return SessionContext::new().read_batch(out_batch);
    }

    let mut out_fields = Vec::with_capacity(data_cols.len() - 1);
    let mut out_cols = Vec::with_capacity(data_cols.len() - 1);
    for prefix_len in 1..data_cols.len() {
        let values = (0..row_count)
            .map(|row_idx| {
                if row_idx + 1 >= row_count {
                    return Ok(false);
                }
                let next_idx = row_idx + 1;
                for arr in data_arrays.iter().take(prefix_len) {
                    let left = ScalarValue::try_from_array(arr.as_ref(), row_idx)?;
                    let right = ScalarValue::try_from_array(arr.as_ref(), next_idx)?;
                    if left != right {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
            .collect::<DataFusionResult<Vec<_>>>()?;
        out_fields.push(Field::new(
            format!("tie_{prefix_len}"),
            DataType::Boolean,
            false,
        ));
        out_cols.push(std::sync::Arc::new(BooleanArray::from(values)) as ArrayRef);
    }

    let out_schema = std::sync::Arc::new(Schema::new(out_fields));
    let out_batch = RecordBatch::try_new(out_schema, out_cols)?;
    SessionContext::new().read_batch(out_batch)
}

fn sort_order_from_hint(
    hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) -> Vec<SortExpr> {
    let schema = hint.data_frame().schema();
    let mut order_by = Vec::new();

    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME)
    {
        order_by.push(col(ACTIVATOR_COL_NAME).sort(false, false));
    }

    let data_fields: Vec<_> = schema
        .fields()
        .iter()
        .filter(|field| !is_system_column(field.name()))
        .collect();
    if !sort_specs.is_empty() {
        let mut ordered = Vec::with_capacity(sort_specs.len());
        for (name, asc, nulls_first) in sort_specs {
            let normalized = normalize_sort_name(name);
            if let Some(field) = data_fields
                .iter()
                .find(|field| normalize_sort_name(field.name()) == normalized)
            {
                // We intentionally force NULLS LAST here to match the deterministic
                // ordering used during padding/rotation and keep prover/verifier aligned.
                let _ = nulls_first;
                ordered.push(col(field.name()).sort(*asc, false));
            }
        }
        if ordered.len() == data_fields.len() {
            order_by.extend(ordered);
        } else {
            order_by.extend(
                data_fields
                    .iter()
                    .map(|field| col(field.name()).sort(true, false)),
            );
        }
    } else {
        order_by.extend(
            data_fields
                .iter()
                .map(|field| col(field.name()).sort(true, false)),
        );
    }

    if schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        // Row-id is only a deterministic tiebreaker once the sort order is fixed.
        order_by.push(col(ROW_ID_COL_NAME).sort(true, true));
    }

    order_by
}

fn normalize_sort_name(name: &str) -> String {
    name.rsplit('.').next().unwrap_or(name).to_string()
}

fn sort_is_asc(sort_specs: &[(String, bool, bool)], col_name: &str) -> bool {
    sort_specs
        .iter()
        .find(|(name, _, _)| normalize_sort_name(name) == normalize_sort_name(col_name))
        .map(|(_, asc, _)| *asc)
        .unwrap_or(true)
}
