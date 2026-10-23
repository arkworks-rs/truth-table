//! The distinct mode of the sort check ([`SortConfig::Distinct`]). Any strict
//! order proves a table's rows distinct, so a hashed column (a string or
//! binary value), whose encoding has no order, is compared on the limbs of its
//! hash slots instead. The check commits the limbs, binds each slot to them
//! with a zerocheck and range-checks them to their widths; as a slot is below
//! `p`, its limbs are then unique, and every compared difference is a
//! range-checked integer.
//!
//! The caller commits the sorted table, so it orders it with
//! [`sort_distinct`], the order this check proves.
//!
//! [`SortConfig::Distinct`]: super::SortConfig::Distinct

use std::sync::Arc;

use arithmetic::encoding::{
    EncodeOptions, STRING_LENGTH_SUFFIX, encode_arrow_array_to_field_with_options,
    hash_slot_limb_widths, hash_slot_limbs, is_hashed_type, segment_base_name,
    segment_suffixes_for_type,
};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use ark_ff::PrimeField;
use datafusion::arrow::{
    array::{ArrayRef, Int64Array, UInt8Array, UInt16Array, new_null_array},
    compute::{SortColumn, SortOptions, concat, concat_batches, lexsort_to_indices, take},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult};

use super::difference_sign_type;
use crate::session::session_context;

/// The columns the distinct sort compares, and how each hash slot splits
/// into limbs.
#[derive(Clone)]
pub(crate) struct DistinctLayout {
    /// The order-preserving columns, then the hash limbs: the compared
    /// columns, in this order.
    pub sort_fields: Vec<Field>,
    pub slots: Vec<HashSlot>,
}

/// One hash slot of a hashed column and its limbs, most significant first.
#[derive(Clone)]
pub(crate) struct HashSlot {
    pub column: String,
    /// The slot's segment suffix (`""` for the primary segment).
    pub suffix: String,
    /// Each limb's field and bit width.
    pub limbs: Vec<(Field, u32)>,
}

impl HashSlot {
    pub fn name(&self) -> String {
        format!("{}{}", self.column, self.suffix)
    }
}

impl DistinctLayout {
    /// The layout of a table with these fields. Row ids, activators and the
    /// auxiliary segments of a column (`__length`, ...) are not compared.
    pub fn new<'a, F: PrimeField>(
        fields: impl IntoIterator<Item = &'a Field>,
    ) -> DataFusionResult<Self> {
        let widths = hash_slot_limb_widths::<F>();
        let mut sort_fields = Vec::new();
        let mut slots = Vec::new();
        for field in fields {
            let name = field.name();
            if is_system_column(name) || segment_base_name(name).is_some() {
                continue;
            }
            let dtype = field.data_type();
            if difference_sign_type(dtype).is_some() {
                sort_fields.push(field.clone());
                continue;
            }
            if !is_hashed_type(dtype) {
                return Err(DataFusionError::Plan(format!(
                    "column {name} of type {dtype} has no order-preserving encoding"
                )));
            }
            for suffix in segment_suffixes_for_type::<F>(dtype) {
                if suffix == STRING_LENGTH_SUFFIX {
                    continue;
                }
                let limbs = widths
                    .iter()
                    .enumerate()
                    .map(|(j, &width)| {
                        let dtype = if width == 8 {
                            DataType::UInt8
                        } else {
                            DataType::UInt16
                        };
                        (
                            Field::new(format!("{name}{suffix}_limb{j}"), dtype, true),
                            width,
                        )
                    })
                    .collect();
                slots.push(HashSlot {
                    column: name.clone(),
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
}

/// `df` collected into one batch, its layout, and the limb columns of its
/// hashed columns in layout order.
fn with_limbs<F: PrimeField>(
    df: DataFrame,
) -> DataFusionResult<(RecordBatch, DistinctLayout, Vec<ArrayRef>)> {
    let arrow_schema = Arc::new(df.schema().as_arrow().clone());
    let batches = crate::session::block_on(df.collect())?;
    let schema = batches.first().map_or(arrow_schema, |batch| batch.schema());
    let batch = concat_batches(&schema, &batches)?;
    let layout = DistinctLayout::new::<F>(schema.fields().iter().map(|field| field.as_ref()))?;
    let rows = batch.num_rows();
    let mut limbs = Vec::new();
    for slot in &layout.slots {
        // The encoder takes a power-of-two length; the extra nulls are cut.
        let column = batch.column_by_name(&slot.column).expect("a layout column");
        let padded = rows.next_power_of_two().max(1);
        let column = concat(&[
            column.as_ref(),
            new_null_array(column.data_type(), padded - rows).as_ref(),
        ])?;
        let segments = encode_arrow_array_to_field_with_options::<F>(&column, EncodeOptions::NONE)
            .map_err(|e| DataFusionError::Execution(format!("hash slot encoding: {e}")))?;
        let values: Vec<Vec<u16>> = segments
            .iter()
            .find(|segment| segment.suffix == slot.suffix)
            .map(|segment| {
                segment
                    .iter_values()
                    .take(rows)
                    .map(hash_slot_limbs::<F>)
                    .collect()
            })
            .unwrap_or_else(|| vec![vec![0; slot.limbs.len()]; rows]);
        for (j, (_, width)) in slot.limbs.iter().enumerate() {
            let limb = values.iter().map(|limbs| limbs[j]);
            let array: ArrayRef = if *width == 8 {
                Arc::new(UInt8Array::from_iter_values(limb.map(|value| value as u8)))
            } else {
                Arc::new(UInt16Array::from_iter_values(limb))
            };
            limbs.push(array);
        }
    }
    Ok((batch, layout, limbs))
}

/// `df`'s rows in the order the distinct sort check proves: active rows
/// first, then ascending on the compared columns, with `__row_id__`
/// renumbered in that order.
pub(crate) fn sort_distinct<F: PrimeField>(df: DataFrame) -> DataFusionResult<DataFrame> {
    let (batch, layout, limbs) = with_limbs::<F>(df)?;
    let limb_names: Vec<&String> = layout.limb_fields().map(|field| field.name()).collect();
    let mut sort_columns = Vec::new();
    if let Some(activator) = batch.column_by_name(ACTIVATOR_COL_NAME) {
        sort_columns.push(SortColumn {
            values: activator.clone(),
            options: Some(SortOptions {
                descending: true,
                nulls_first: false,
            }),
        });
    }
    for field in &layout.sort_fields {
        let values = match limb_names.iter().position(|name| *name == field.name()) {
            Some(idx) => limbs[idx].clone(),
            None => batch
                .column_by_name(field.name())
                .expect("a layout column")
                .clone(),
        };
        sort_columns.push(SortColumn {
            values,
            options: Some(SortOptions {
                descending: false,
                nulls_first: false,
            }),
        });
    }
    let indices = lexsort_to_indices(&sort_columns, None)?;
    let columns = batch
        .schema()
        .fields()
        .iter()
        .zip(batch.columns())
        .map(|(field, column)| {
            if field.name() == ROW_ID_COL_NAME {
                Ok(Arc::new(Int64Array::from_iter_values(0..batch.num_rows() as i64)) as ArrayRef)
            } else {
                take(column.as_ref(), &indices, None).map_err(Into::into)
            }
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    session_context().read_batch(RecordBatch::try_new(batch.schema(), columns)?)
}

/// The table the distinct sort compares: `df`'s order-preserving columns,
/// the limbs and the activator, in `df`'s row order.
pub(crate) fn distinct_view<F: PrimeField>(df: DataFrame) -> DataFusionResult<DataFrame> {
    let (batch, layout, limbs) = with_limbs::<F>(df)?;
    let mut fields = Vec::new();
    let mut columns = Vec::new();
    let mut limbs = limbs.into_iter();
    for field in &layout.sort_fields {
        let column = match batch.column_by_name(field.name()) {
            Some(column) => column.clone(),
            None => limbs.next().expect("one array per limb"),
        };
        fields.push(field.clone());
        columns.push(column);
    }
    if let Some(activator) = batch.column_by_name(ACTIVATOR_COL_NAME) {
        fields.push(arithmetic::ACTIVATOR_FIELD.as_ref().clone());
        columns.push(activator.clone());
    }
    session_context().read_batch(RecordBatch::try_new(
        Arc::new(Schema::new(fields)),
        columns,
    )?)
}

/// The schema of [`distinct_view`], for verifier planning.
pub(crate) fn distinct_view_fields(fields: &[Field], layout: &DistinctLayout) -> Vec<Field> {
    let mut view = layout.sort_fields.clone();
    if fields
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME)
    {
        view.push(arithmetic::ACTIVATOR_FIELD.as_ref().clone());
    }
    view
}
