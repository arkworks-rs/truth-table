use crate::irs::nodes::utils::contig_sort::{
    DIFF_INPUT_LABEL, ROTATED_INPUT_LABEL, TIE_INDICATOR_LABEL, difference_sign_type,
    ordered_data_fields_for_hint,
};
use crate::session::session_context;
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use datafusion::arrow::{
    array::{Array, ArrayRef, BooleanArray, Int64Array, new_null_array},
    compute::{concat, concat_batches},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::logical_expr::Expr;
use datafusion::logical_expr::col;
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion_expr::SortExpr;

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

    if let Some(tie_df) = tie_indicator_on_ordered(ordered.clone(), order_by, sort_specs)
        .expect("sort tie indicator planning should succeed")
    {
        let tie_should_materialize = tie_df
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), true))
            .collect();
        let tie_hint = crate::irs::nodes::hints::HintDF::new(tie_df, tie_should_materialize);
        gadget_payload.insert(TIE_INDICATOR_LABEL.to_string(), tie_hint);
    }

    let sign_only_fields: Vec<Field> = ordered_data_fields_for_hint(input_hint, sort_specs)
        .into_iter()
        .filter(|field| difference_sign_type(field.data_type()).is_none())
        .collect();
    if !sign_only_fields.is_empty() {
        let diff_df = sign_only_diff_on_ordered(ordered, &sign_only_fields, sort_specs)
            .expect("sort diff planning should succeed");
        let diff_should_materialize = diff_df
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), true))
            .collect();
        let diff_hint = crate::irs::nodes::hints::HintDF::new(diff_df, diff_should_materialize);
        gadget_payload.insert(DIFF_INPUT_LABEL.to_string(), diff_hint);
    }
}

pub(crate) fn sort_input_for_contig_sort(
    input_hint: &crate::irs::nodes::hints::HintDF,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let order_by = sort_order_from_hint(input_hint, sort_specs);
    input_hint.data_frame().clone().sort(order_by)
}

/// The rotated table has no row ids and no activator: the sort check gives it
/// the public mask `C_{µ,s-1}`.
fn is_rotation_excluded(name: &str) -> bool {
    name == ROW_ID_COL_NAME || name == ACTIVATOR_COL_NAME
}

pub(crate) fn rotate(
    df: DataFrame,
    order_by: Vec<SortExpr>,
    skip_collection: bool,
) -> DataFusionResult<DataFrame> {
    if skip_collection {
        // Verifier planning must not collect data: project the non-row-id
        // columns to get the schema the downstream gadgets expect.
        let projected: Vec<Expr> = df
            .schema()
            .fields()
            .iter()
            .filter(|field| !is_rotation_excluded(field.name()))
            .map(|field| col(field.name()))
            .collect();
        return df.select(projected);
    }

    // `d'[j] = d[j + 1]`. Only rows `j < s - 1` are read, so the last row
    // (here `d[0]`) is arbitrary.
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
    // Collect to Arrow to pad deterministically and then rotate the arrays explicitly.
    if skip_collection {
        return Err(DataFusionError::Execution(
            "verifier planning must not collect DataFrames".to_string(),
        ));
    }
    let batches = crate::session::block_on(ordered.collect())?;
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
        if is_rotation_excluded(field.name()) {
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
    session_context().read_batch(out_batch)
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
        scalar.to_array_of_size(len)
    } else {
        Ok(new_null_array(data_type, len))
    }
}

/// The shifted sign `{0, 1, 2}` of each adjacent pair, for the keys in
/// `fields` (those without a `difference_sign_type`).
fn sign_only_diff_on_ordered(
    ordered: DataFrame,
    fields: &[Field],
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<DataFrame> {
    let batches = crate::session::block_on(ordered.collect())?;
    if batches.is_empty() {
        return Err(DataFusionError::Execution(
            "sign-only diff input produced no batches".to_string(),
        ));
    }
    let schema_ref = batches[0].schema();
    let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
    let combined = concat_batches(&schema_ref, batch_refs)?;
    let row_count = combined.num_rows();

    let mut out_fields = Vec::with_capacity(fields.len());
    let mut out_cols = Vec::with_capacity(fields.len());
    for field in fields {
        let source = combined
            .column(combined.schema().index_of(field.name())?)
            .clone();
        let rotated = rotate_array(source.clone(), row_count)?;
        let (lhs, rhs) = if sort_is_asc(sort_specs, field.name()) {
            (rotated.as_ref(), source.as_ref())
        } else {
            (source.as_ref(), rotated.as_ref())
        };
        out_fields.push(Field::new(field.name(), DataType::UInt8, true));
        out_cols.push(sign_only_diff_array(lhs, rhs)?);
    }

    let out_schema = std::sync::Arc::new(Schema::new(out_fields));
    let out_batch = RecordBatch::try_new(out_schema, out_cols)?;
    session_context().read_batch(out_batch)
}

fn rotate_array(source: ArrayRef, row_count: usize) -> DataFusionResult<ArrayRef> {
    if row_count <= 1 {
        return Ok(source);
    }
    let tail = source.slice(1, row_count - 1);
    let head = source.slice(0, 1);
    concat(&[tail.as_ref(), head.as_ref()]).map_err(Into::into)
}

fn sign_only_diff_array(lhs: &dyn Array, rhs: &dyn Array) -> DataFusionResult<ArrayRef> {
    let values = (0..lhs.len())
        .map(|idx| {
            if lhs.is_null(idx) || rhs.is_null(idx) {
                Ok(None)
            } else {
                let left = ScalarValue::try_from_array(lhs, idx)?;
                let right = ScalarValue::try_from_array(rhs, idx)?;
                let shifted: u8 = match left.partial_cmp(&right) {
                    Some(std::cmp::Ordering::Greater) => 2,
                    Some(std::cmp::Ordering::Less) => 0,
                    _ => 1,
                };
                Ok(Some(shifted))
            }
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    Ok(std::sync::Arc::new(
        datafusion::arrow::array::UInt8Array::from(values),
    ))
}

/// Builds the committed tie indicators `tie_1..tie_{k-1}`: `tie_j` is true on
/// row i iff rows i and i+1 match on the first `j` keys. `None` for fewer
/// than two keys, where only the public `tie_0` remains.
fn tie_indicator_on_ordered(
    ordered: DataFrame,
    order_by: Vec<SortExpr>,
    sort_specs: &[(String, bool, bool)],
) -> DataFusionResult<Option<DataFrame>> {
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
        if ordered_cols.len() == sort_specs.len() {
            data_cols = ordered_cols;
        }
    }
    if data_cols.len() < 2 {
        return Ok(None);
    }
    // Materialize ties from the already sorted batch so the tie rows are aligned
    // with the same physical row order consumed by TABLE/ROTATED/DIFF.
    let ordered = if order_by.is_empty() {
        ordered
    } else {
        ordered.sort(order_by)?
    };
    let batches = crate::session::block_on(ordered.collect())?;
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
    session_context().read_batch(out_batch).map(Some)
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
                // Force NULLS LAST to match the ordering used during padding and
                // rotation and keep prover and verifier aligned.
                let _ = nulls_first;
                ordered.push(col(field.name()).sort(*asc, false));
            }
        }
        if ordered.len() == sort_specs.len() {
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
