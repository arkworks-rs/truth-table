use crate::irs::nodes::utils::contig_sort::sort_distinct;
use crate::session::session_context;
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_FIELD, is_system_column};
use ark_ff::PrimeField;
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray, Int64Array, UInt32Array, new_null_array},
        compute::{concat, concat_batches, take},
        datatypes::Schema,
        record_batch::RecordBatch,
    },
    prelude::DataFrame,
};
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion_expr::{Expr, col, lit};
use std::{collections::HashSet, sync::Arc};

use crate::irs::nodes::hints::sort_by_row_id_if_present;

/// The distinct active keys of both sides, padded with inactive rows and
/// sorted with [`sort_distinct`]. Returns the union and its number of active
/// rows `t`.
pub(crate) fn build_union_hint_df<F: PrimeField>(
    left: DataFrame,
    right: DataFrame,
) -> DataFusionResult<(DataFrame, usize)> {
    ensure_union_input_shape(&left, "left")?;
    ensure_union_input_shape(&right, "right")?;
    let left_active = project_active_key_rows(left)?;
    let right_active = project_active_key_rows(right)?;
    let key_names = data_column_names(&left_active)?;

    let unioned = left_active.union(right_active)?;
    let (union, active_rows) = materialize_union_hint(unioned, &key_names)?;
    Ok((sort_distinct::<F>(union)?, active_rows))
}

fn ensure_union_input_shape(df: &DataFrame, side: &str) -> DataFusionResult<()> {
    let has_row_id = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == arithmetic::ROW_ID_COL_NAME);
    if !has_row_id {
        return Err(DataFusionError::Plan(format!(
            "match-pair union hint {side} input is missing {}",
            arithmetic::ROW_ID_COL_NAME
        )));
    }
    let has_activator = df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    if !has_activator {
        return Err(DataFusionError::Plan(format!(
            "match-pair union hint {side} input is missing {ACTIVATOR_COL_NAME}"
        )));
    }
    Ok(())
}

fn project_active_key_rows(df: DataFrame) -> DataFusionResult<DataFrame> {
    let sorted_df = sort_by_row_id_if_present(df)?;
    let active_df = if sorted_df
        .schema()
        .iter()
        .any(|(_, field)| field.name() == ACTIVATOR_COL_NAME)
    {
        sorted_df.filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))?
    } else {
        sorted_df
    };

    let key_exprs: Vec<Expr> = active_df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            (!is_system_column(field.name())).then_some(
                Expr::Column(datafusion_common::Column::new(
                    qualifier.cloned(),
                    field.name(),
                ))
                .alias(field.name()),
            )
        })
        .collect();
    if key_exprs.is_empty() {
        return Err(DataFusionError::Plan(
            "match-pair union hint requires at least one data column".to_string(),
        ));
    }
    active_df.select(key_exprs)
}

fn data_column_names(df: &DataFrame) -> DataFusionResult<Vec<String>> {
    let key_names: Vec<String> = df
        .schema()
        .fields()
        .iter()
        .filter_map(|field| (!is_system_column(field.name())).then_some(field.name().to_string()))
        .collect();
    if key_names.is_empty() {
        return Err(DataFusionError::Plan(
            "match-pair union hint requires at least one data column".to_string(),
        ));
    }
    Ok(key_names)
}

fn materialize_union_hint(
    df: DataFrame,
    key_names: &[String],
) -> DataFusionResult<(DataFrame, usize)> {
    let batches = crate::session::block_on(collect_in_partition_order(df.clone()))?;
    let schema_ref = if batches.is_empty() {
        Arc::new(df.schema().as_arrow().clone())
    } else {
        batches[0].schema()
    };
    let combined = if batches.is_empty() {
        RecordBatch::new_empty(schema_ref.clone())
    } else {
        let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
        concat_batches(&schema_ref, batch_refs)?
    };
    let deduped = deduplicate_key_rows(&combined, key_names)?;
    let row_count = deduped.num_rows();
    // At least two rows: a one-row union would be a zero-variable table,
    // which the sort and shift checks do not support.
    let target = row_count.next_power_of_two().max(2);
    let pad = target.saturating_sub(row_count);

    let mut output_fields = Vec::with_capacity(key_names.len() + 2);
    let mut output_arrays = Vec::with_capacity(key_names.len() + 2);
    for key in key_names {
        let idx = deduped.schema().index_of(key)?;
        let field = deduped.schema().field(idx).clone();
        let base = deduped.column(idx).clone();
        let padded = if pad == 0 {
            base
        } else {
            let pad_arr: ArrayRef = new_null_array(field.data_type(), pad);
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        };
        output_fields.push(field.with_nullable(true));
        output_arrays.push(padded);
    }
    output_fields.push((**ROW_ID_FIELD).clone());
    output_arrays.push(Arc::new(Int64Array::from_iter_values(
        (0..target).map(|idx| idx as i64),
    )) as _);

    let mut activator_vals = Vec::with_capacity(target);
    activator_vals.extend(std::iter::repeat_n(true, row_count));
    activator_vals.extend(std::iter::repeat_n(false, pad));
    output_fields.push((**ACTIVATOR_FIELD).clone());
    output_arrays.push(Arc::new(BooleanArray::from(activator_vals)) as _);

    let out_schema = Arc::new(Schema::new(output_fields));
    let out_batch = RecordBatch::try_new(out_schema, output_arrays)?;
    Ok((session_context().read_batch(out_batch)?, row_count))
}

fn deduplicate_key_rows(
    batch: &RecordBatch,
    key_names: &[String],
) -> DataFusionResult<RecordBatch> {
    if batch.num_rows() <= 1 {
        return Ok(batch.clone());
    }

    let key_indices: Vec<usize> = key_names
        .iter()
        .map(|key| batch.schema().index_of(key))
        .collect::<Result<_, _>>()?;

    let mut seen = HashSet::with_capacity(batch.num_rows());
    let mut keep = Vec::with_capacity(batch.num_rows());
    for row in 0..batch.num_rows() {
        let tuple = key_indices
            .iter()
            .map(|idx| ScalarValue::try_from_array(batch.column(*idx), row))
            .collect::<DataFusionResult<Vec<_>>>()?;
        // The union hint is a set over full key tuples. Keep the first active
        // occurrence and drop any later duplicate tuple from either side.
        if seen.insert(tuple) {
            keep.push(row as u32);
        }
    }

    if keep.len() == batch.num_rows() {
        return Ok(batch.clone());
    }

    let indices = UInt32Array::from(keep);
    let arrays = batch
        .columns()
        .iter()
        .map(|column| take(column.as_ref(), &indices, None))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RecordBatch::try_new(batch.schema(), arrays)?)
}

/// The dataframe's rows, one partition after the other. A union has a
/// partition for each input, and `collect` merges partitions in the order
/// their batches arrive. The hint keeps the first occurrence of a key, so
/// its rows would depend on which side was faster.
async fn collect_in_partition_order(df: DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
    Ok(df
        .collect_partitioned()
        .await?
        .into_iter()
        .flatten()
        .collect())
}
