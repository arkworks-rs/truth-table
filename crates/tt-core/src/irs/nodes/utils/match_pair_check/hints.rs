use crate::irs::nodes::utils::contig_sort::difference_sign_type;
use crate::session::session_context;
use arithmetic::encoding::{
    EncodeOptions, STRING_LENGTH_SUFFIX, encode_arrow_array_to_field_with_options,
    hash_slot_limb_widths, hash_slot_limbs, is_hashed_type, segment_suffixes_for_type,
};
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_FIELD, is_system_column};
use ark_ff::PrimeField;
use datafusion::{
    arrow::{
        array::{
            Array, ArrayRef, BooleanArray, Int64Array, UInt8Array, UInt16Array, UInt32Array,
            new_null_array,
        },
        compute::{SortColumn, SortOptions, concat, concat_batches, lexsort_to_indices, take},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    prelude::DataFrame,
};
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use datafusion_expr::{Expr, col, lit};
use indexmap::IndexMap;
use std::{collections::HashSet, sync::Arc};

use crate::irs::nodes::hints::sort_by_row_id_if_present;

/// The column layout of the union `û`: its sort key, and how each hash slot
/// of a hashed key splits into limbs.
#[derive(Clone)]
pub(crate) struct UnionLayout {
    /// The sort key: the order-preserving keys, then the hash limbs, in the
    /// union's column order. Each adjacent difference is then a
    /// range-checked integer, which a hash's is not.
    pub sort_fields: Vec<Field>,
    pub slots: Vec<HashSlot>,
}

/// One hash slot of a hashed key and its limbs, most significant first.
#[derive(Clone)]
pub(crate) struct HashSlot {
    pub key: String,
    /// The slot's segment suffix (`""` for the primary segment).
    pub suffix: String,
    /// Each limb's field and bit width.
    pub limbs: Vec<(Field, u32)>,
}

impl HashSlot {
    pub fn name(&self) -> String {
        format!("{}{}", self.key, self.suffix)
    }
}

impl UnionLayout {
    pub fn new<F: PrimeField>(key_fields: &[Field]) -> DataFusionResult<Self> {
        let widths = hash_slot_limb_widths::<F>();
        let mut sort_fields = Vec::new();
        let mut slots = Vec::new();
        for key in key_fields {
            let dtype = key.data_type();
            if difference_sign_type(dtype).is_some() {
                sort_fields.push(Field::new(key.name(), dtype.clone(), true));
                continue;
            }
            if !is_hashed_type(dtype) {
                return Err(DataFusionError::Plan(format!(
                    "a many-to-many join key of type {dtype} has no order-preserving encoding"
                )));
            }
            for suffix in segment_suffixes_for_type::<F>(dtype) {
                if suffix == STRING_LENGTH_SUFFIX {
                    continue;
                }
                let limbs: Vec<(Field, u32)> = widths
                    .iter()
                    .enumerate()
                    .map(|(j, &width)| {
                        let dtype = if width == 8 {
                            DataType::UInt8
                        } else {
                            DataType::UInt16
                        };
                        let name = format!("{}{suffix}_limb{j}", key.name());
                        (Field::new(name, dtype, false), width)
                    })
                    .collect();
                slots.push(HashSlot {
                    key: key.name().clone(),
                    suffix,
                    limbs,
                });
            }
        }
        let mut layout = Self { sort_fields, slots };
        let limbs: Vec<Field> = layout.limb_fields().cloned().collect();
        layout.sort_fields.extend(limbs);
        Ok(layout)
    }

    pub fn limb_fields(&self) -> impl Iterator<Item = &Field> {
        self.slots
            .iter()
            .flat_map(|slot| slot.limbs.iter().map(|(field, _)| field))
    }

    pub fn is_limb(&self, name: &str) -> bool {
        self.limb_fields().any(|field| field.name() == name)
    }

    /// The union's fields: the keys, the limbs, the row id and the activator.
    pub fn union_fields(&self, key_fields: &[Field]) -> Vec<Field> {
        let mut fields = key_fields.to_vec();
        fields.extend(self.limb_fields().cloned());
        fields.push((**ROW_ID_FIELD).clone());
        fields.push((**ACTIVATOR_FIELD).clone());
        fields
    }
}

/// The distinct active keys of both sides, with the limbs of `layout`,
/// sorted strictly by `layout.sort_fields` and padded with inactive rows.
/// Returns the union and its number of active rows `t`.
pub(crate) fn build_union_hint_df<F: PrimeField>(
    left: DataFrame,
    right: DataFrame,
    layout: &UnionLayout,
) -> DataFusionResult<(DataFrame, usize)> {
    ensure_union_input_shape(&left, "left")?;
    ensure_union_input_shape(&right, "right")?;
    let left_active = project_active_key_rows(left)?;
    let right_active = project_active_key_rows(right)?;
    let key_names = data_column_names(&left_active)?;

    let unioned = left_active.union(right_active)?;
    materialize_union_hint::<F>(unioned, &key_names, layout)
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

fn materialize_union_hint<F: PrimeField>(
    df: DataFrame,
    key_names: &[String],
    layout: &UnionLayout,
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

    let mut columns: Vec<(Field, ArrayRef)> = Vec::with_capacity(key_names.len());
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
        columns.push((field.with_nullable(true), padded));
    }
    // The limbs split the encoded slots, so the padding nulls are encoded
    // too: their slots are zero.
    let mut encoded = IndexMap::new();
    for slot in &layout.slots {
        if !encoded.contains_key(&slot.key) {
            let (_, array) = columns
                .iter()
                .find(|(field, _)| field.name() == &slot.key)
                .ok_or_else(|| {
                    DataFusionError::Plan(format!("match-pair key column missing: {}", slot.key))
                })?;
            let segments =
                encode_arrow_array_to_field_with_options::<F>(array, EncodeOptions::NONE).map_err(
                    |e| DataFusionError::Execution(format!("match-pair key encoding: {e}")),
                )?;
            encoded.insert(slot.key.clone(), segments);
        }
        let values: Vec<Vec<u16>> = encoded[&slot.key]
            .iter()
            .find(|segment| segment.suffix == slot.suffix)
            .map(|segment| segment.iter_values().map(hash_slot_limbs::<F>).collect())
            .unwrap_or_else(|| vec![vec![0; slot.limbs.len()]; target]);
        for (j, (field, width)) in slot.limbs.iter().enumerate() {
            let array: ArrayRef = if *width == 8 {
                Arc::new(UInt8Array::from_iter_values(
                    values.iter().map(|limbs| limbs[j] as u8),
                ))
            } else {
                Arc::new(UInt16Array::from_iter_values(
                    values.iter().map(|limbs| limbs[j]),
                ))
            };
            columns.push((field.clone(), array));
        }
    }

    // Sort the active rows; the padding stays last.
    let sort_columns = layout
        .sort_fields
        .iter()
        .map(|sort_field| {
            let (_, array) = columns
                .iter()
                .find(|(field, _)| field.name() == sort_field.name())
                .ok_or_else(|| {
                    DataFusionError::Plan(format!(
                        "match-pair sort column missing: {}",
                        sort_field.name()
                    ))
                })?;
            Ok(SortColumn {
                values: array.slice(0, row_count),
                options: Some(SortOptions {
                    descending: false,
                    nulls_first: false,
                }),
            })
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    let order = lexsort_to_indices(&sort_columns, None)?;
    let indices = UInt32Array::from_iter_values(
        order
            .values()
            .iter()
            .copied()
            .chain(row_count as u32..target as u32),
    );

    let mut output_fields = Vec::with_capacity(columns.len() + 2);
    let mut output_arrays = Vec::with_capacity(columns.len() + 2);
    for (field, array) in columns {
        output_fields.push(field);
        output_arrays.push(take(array.as_ref(), &indices, None)?);
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
