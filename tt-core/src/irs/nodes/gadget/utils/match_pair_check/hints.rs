use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_FIELD, is_system_column};
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray, Int64Array, UInt32Array, new_null_array},
        compute::{concat, concat_batches, take},
        datatypes::{Field, Schema},
        record_batch::RecordBatch,
    },
    prelude::{DataFrame, SessionContext},
};
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion_expr::{Expr, col, lit};
use std::{collections::HashSet, sync::Arc};
use tokio::runtime::RuntimeFlavor;

use crate::irs::nodes::hints::sort_by_row_id_if_present;

pub(crate) fn build_union_hint_df(
    left: DataFrame,
    right: DataFrame,
) -> DataFusionResult<DataFrame> {
    ensure_union_input_shape(&left, "left")?;
    ensure_union_input_shape(&right, "right")?;
    let left_active = project_active_key_rows(left)?;
    let right_active = project_active_key_rows(right)?;
    let key_names = data_column_names(&left_active)?;

    let unioned = left_active.union(right_active)?;
    materialize_union_hint(unioned, &key_names)
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

fn materialize_union_hint(df: DataFrame, key_names: &[String]) -> DataFusionResult<DataFrame> {
    let batches = collect_blocking(df.clone())?;
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
    let target = if row_count == 0 {
        2
    } else {
        row_count.next_power_of_two()
    };
    let pad = target.saturating_sub(row_count);

    let mut output_fields = Vec::with_capacity(key_names.len() + 2);
    let mut output_arrays = Vec::with_capacity(key_names.len() + 2);

    for key in key_names {
        let (idx, field) = deduped
            .schema()
            .fields()
            .iter()
            .enumerate()
            .find(|(_, field)| field.name() == key)
            .map(|(idx, field)| (idx, field.clone()))
            .ok_or_else(|| {
                DataFusionError::Plan(format!("match-pair key column missing: {key}"))
            })?;
        let base = deduped.column(idx).clone();
        output_fields.push(Field::new(
            field.name(),
            field.data_type().clone(),
            field.is_nullable() || pad > 0,
        ));
        let out = if pad == 0 {
            base
        } else {
            let pad_arr: ArrayRef = new_null_array(field.data_type(), pad);
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        };
        output_arrays.push(out);
    }

    // Fresh row ids are assigned after the set-union is materialized and padded so
    // downstream gadgets see a dense 0..2^k-1 domain.
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
    SessionContext::new().read_batch(out_batch)
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
    use super::build_union_hint_df;
    use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
    use datafusion::{
        arrow::{
            array::{ArrayRef, BooleanArray, Int64Array},
            compute::concat_batches,
            datatypes::{DataType, Field, Schema},
            record_batch::RecordBatch,
        },
        prelude::SessionContext,
    };
    use datafusion_common::ScalarValue;
    use std::sync::Arc;

    fn build_df(
        data_columns: &[(&str, Vec<i64>)],
        activators: Vec<bool>,
        row_ids: Vec<i64>,
    ) -> datafusion::prelude::DataFrame {
        let mut fields = data_columns
            .iter()
            .map(|(name, _)| Field::new(*name, DataType::Int64, false))
            .collect::<Vec<_>>();
        fields.push(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false));
        fields.push(Field::new(ROW_ID_COL_NAME, DataType::Int64, false));

        let mut arrays = data_columns
            .iter()
            .map(|(_, values)| Arc::new(Int64Array::from(values.clone())) as ArrayRef)
            .collect::<Vec<_>>();
        arrays.push(Arc::new(BooleanArray::from(activators)) as ArrayRef);
        arrays.push(Arc::new(Int64Array::from(row_ids)) as ArrayRef);

        let batch =
            RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).expect("record batch");
        SessionContext::new().read_batch(batch).expect("dataframe")
    }

    fn build_expected_df(
        data_columns: &[(&str, Vec<Option<i64>>)],
        activators: Vec<bool>,
        row_ids: Vec<i64>,
    ) -> datafusion::prelude::DataFrame {
        let mut fields = data_columns
            .iter()
            .map(|(name, _)| Field::new(*name, DataType::Int64, true))
            .collect::<Vec<_>>();
        fields.push(Field::new(ROW_ID_COL_NAME, DataType::Int64, false));
        fields.push(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false));

        let mut arrays = data_columns
            .iter()
            .map(|(_, values)| Arc::new(Int64Array::from(values.clone())) as ArrayRef)
            .collect::<Vec<_>>();
        arrays.push(Arc::new(Int64Array::from(row_ids)) as ArrayRef);
        arrays.push(Arc::new(BooleanArray::from(activators)) as ArrayRef);

        let batch =
            RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).expect("record batch");
        SessionContext::new().read_batch(batch).expect("dataframe")
    }

    fn collect_single_batch(df: datafusion::prelude::DataFrame) -> RecordBatch {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let batches = rt.block_on(df.collect()).expect("collect");
        assert!(!batches.is_empty(), "expected union result to contain rows");
        let schema = batches[0].schema();
        let refs = batches.iter().collect::<Vec<_>>();
        concat_batches(&schema, refs).expect("concat batches")
    }

    fn collect_rows(df: datafusion::prelude::DataFrame) -> Vec<Vec<ScalarValue>> {
        let batch = collect_single_batch(df);
        (0..batch.num_rows())
            .map(|row| {
                (0..batch.num_columns())
                    .map(|col| ScalarValue::try_from_array(batch.column(col), row).expect("value"))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn build_union_hint_df_single_data_column() {
        // Scenario: one key column with inactive rows and duplicates across the two
        // inputs. The union hint should keep only active unique values, assign fresh
        // row ids, and pad the result to the next power of two.
        let left = build_df(
            &[("c0", vec![1, 2, 2])],
            vec![true, true, false],
            vec![4, 1, 7],
        );
        let right = build_df(&[("c0", vec![2, 4])], vec![true, true], vec![2, 3]);

        let actual = collect_rows(build_union_hint_df(left, right).expect("union hint"));
        let expected = collect_rows(build_expected_df(
            &[("c0", vec![Some(1), Some(2), Some(4), None])],
            vec![true, true, true, false],
            vec![0, 1, 2, 3],
        ));
        assert_eq!(actual, expected);
    }

    #[test]
    fn build_union_hint_df_two_data_columns() {
        // Scenario: two-column composite keys. The union hint should deduplicate full
        // tuples, not individual columns, while preserving first-seen order across
        // left then right active rows.
        let left = build_df(
            &[("c0", vec![1, 1, 3]), ("c1", vec![2, 4, 5])],
            vec![true, true, true],
            vec![11, 7, 19],
        );
        let right = build_df(
            &[("c0", vec![1, 2, 3]), ("c1", vec![4, 8, 8])],
            vec![true, true, true],
            vec![13, 5, 17],
        );

        let actual = collect_rows(build_union_hint_df(left, right).expect("union hint"));
        let expected = collect_rows(build_expected_df(
            &[
                (
                    "c0",
                    vec![
                        Some(1),
                        Some(1),
                        Some(3),
                        Some(2),
                        Some(3),
                        None,
                        None,
                        None,
                    ],
                ),
                (
                    "c1",
                    vec![
                        Some(2),
                        Some(4),
                        Some(5),
                        Some(8),
                        Some(8),
                        None,
                        None,
                        None,
                    ],
                ),
            ],
            vec![true, true, true, true, true, false, false, false],
            vec![0, 1, 2, 3, 4, 5, 6, 7],
        ));
        assert_eq!(actual, expected);
    }

    #[test]
    fn build_union_hint_df_three_data_columns() {
        // Scenario: three-column keys with duplicates and inactive rows on both sides.
        // The union hint should keep active unique triples and still synthesize a dense
        // row-id/activator tail after padding.
        let left = build_df(
            &[
                ("c0", vec![1, 2]),
                ("c1", vec![10, 20]),
                ("c2", vec![100, 200]),
            ],
            vec![true, false],
            vec![9, 3],
        );
        let right = build_df(
            &[
                ("c0", vec![1, 3, 4]),
                ("c1", vec![10, 30, 40]),
                ("c2", vec![100, 300, 400]),
            ],
            vec![true, true, true],
            vec![4, 8, 12],
        );

        let actual = collect_rows(build_union_hint_df(left, right).expect("union hint"));
        let expected = collect_rows(build_expected_df(
            &[
                ("c0", vec![Some(1), Some(3), Some(4), None]),
                ("c1", vec![Some(10), Some(30), Some(40), None]),
                ("c2", vec![Some(100), Some(300), Some(400), None]),
            ],
            vec![true, true, true, false],
            vec![0, 1, 2, 3],
        ));
        assert_eq!(actual, expected);
    }
}
