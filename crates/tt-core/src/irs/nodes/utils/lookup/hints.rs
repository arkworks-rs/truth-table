//! Plan-time construction of the lookup `multiplicity` witness as a
//! `HintDF`: the standard materialization → arithmetization → commitment →
//! tracking pipeline then turns it into a `TrackedTable` in the payload, like
//! any base-table column.
//!
//! For each row `i` of the super table (in row-id order):
//! - `multiplicity[i] = 0` if super's activator at row `i` is 0.
//! - `multiplicity[i] = 0` if super's key tuple at row `i` occurs at an
//!   earlier active super row (the HintedLookupPIOP only counts against the
//!   first occurrence).
//! - Otherwise `multiplicity[i]` is the number of active included rows whose
//!   key tuple equals super's at row `i`.
//!
//! The verifier's HintDF must have the same schema and `should_materialize`
//! flags as the prover's, because the tracking pass consumes commitments in
//! the same field order on both sides. Its data values are unused (the
//! verifier does not run materialization).

use crate::session::session_context;
use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, is_system_column};
use datafusion::arrow::row::{RowConverter, Rows, SortField};
use datafusion::arrow::{
    array::{Array, ArrayRef, BooleanArray, Int64Array},
    datatypes::{DataType, Field, FieldRef, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use indexmap::IndexMap;
use rayon::prelude::*;

use super::first_occurrence_counts;

use crate::irs::nodes::hints::HintDF;

/// The multiplicity HintDF of a lookup gadget, from the plan-time super and
/// included HintDFs of an upstream gadget (typically `supp`). Collects both
/// eagerly and wraps the result in a MemTable-backed DataFrame.
///
/// Fails if an input DataFrame cannot be collected or if the two disagree
/// on the number or types of data columns.
pub fn build_multiplicity_hint(
    super_hint: &HintDF,
    included_hint: &HintDF,
) -> DataFusionResult<HintDF> {
    let super_df = super_hint.data_frame().clone();
    let included_df = included_hint.data_frame().clone();

    let (super_data_cols, super_types) = data_columns(&super_df);
    let (included_data_cols, included_types) = data_columns(&included_df);
    if super_data_cols.len() != included_data_cols.len() {
        return Err(DataFusionError::Plan(format!(
            "lookup multiplicity hint: super has {} data columns but included has {}",
            super_data_cols.len(),
            included_data_cols.len()
        )));
    }
    if super_types != included_types {
        return Err(DataFusionError::Plan(format!(
            "lookup multiplicity hint: super key types {super_types:?} differ from included {included_types:?}"
        )));
    }

    let (super_batches, included_batches) = rayon::join(
        || crate::session::block_on(super_df.collect()),
        || crate::session::block_on(included_df.collect()),
    );
    let (super_batches, included_batches) = (super_batches?, included_batches?);

    let super_active = active_mask_from_batches(&super_batches);
    let included_active = active_mask_from_batches(&included_batches);
    let multiplicities = if super_data_cols.is_empty() {
        first_occurrence_counts(|_| (), &super_active, |_| (), &included_active)
    } else {
        // Row-format bytes are equal exactly when the ScalarValue tuples are
        // (NULL equals NULL, floats compare by bits), provided both sides
        // share one converter and so one key type per column.
        let converter = RowConverter::new(super_types.into_iter().map(SortField::new).collect())?;
        let super_rows = key_rows(&super_batches, &super_data_cols, &converter)?;
        let included_rows = key_rows(&included_batches, &included_data_cols, &converter)?;
        fn flatten(rows: &[Rows]) -> Vec<&[u8]> {
            rows.iter()
                .flat_map(|r| r.iter().map(|row| row.data()))
                .collect()
        }
        let (super_keys, included_keys) = (flatten(&super_rows), flatten(&included_rows));
        first_occurrence_counts(
            |row| super_keys[row],
            &super_active,
            |row| included_keys[row],
            &included_active,
        )
    };

    build_hint_from_values(multiplicities, super_active)
}

/// Schema-matching HintDF for the verifier side. Verifier planning must not
/// collect DataFrames, and the tracking pass only reads the schema and the
/// `should_materialize` flags, so the data is a one-row placeholder.
pub fn build_multiplicity_hint_schema_only(_super_hint: &HintDF) -> DataFusionResult<HintDF> {
    build_hint_from_values(vec![0], vec![false])
}

fn data_columns(df: &DataFrame) -> (Vec<String>, Vec<DataType>) {
    df.schema()
        .fields()
        .iter()
        .filter(|field| !is_system_column(field.name()))
        .map(|field| (field.name().to_string(), field.data_type().clone()))
        .unzip()
}

fn active_mask_from_batches(batches: &[RecordBatch]) -> Vec<bool> {
    let mut out = Vec::new();
    for batch in batches {
        let activator_idx = batch
            .schema()
            .fields()
            .iter()
            .position(|f| f.name() == ACTIVATOR_COL_NAME);
        match activator_idx {
            Some(idx) => {
                let col = batch.column(idx);
                if let Some(bool_col) = col.as_any().downcast_ref::<BooleanArray>() {
                    for i in 0..bool_col.len() {
                        out.push(!bool_col.is_null(i) && bool_col.value(i));
                    }
                } else {
                    // Non-boolean activator: treat any non-null value as active.
                    for i in 0..col.len() {
                        let is_active = !col.is_null(i)
                            && !ScalarValue::try_from_array(col.as_ref(), i)
                                .map(|s| s.is_null())
                                .unwrap_or(true);
                        out.push(is_active);
                    }
                }
            }
            None => {
                // No activator column → every row is active.
                out.extend(std::iter::repeat_n(true, batch.num_rows()));
            }
        }
    }
    out
}

fn key_rows(
    batches: &[RecordBatch],
    key_cols: &[String],
    converter: &RowConverter,
) -> DataFusionResult<Vec<Rows>> {
    batches
        .par_iter()
        .map(|batch| {
            let columns = key_cols
                .iter()
                .map(|name| {
                    batch.column_by_name(name).cloned().ok_or_else(|| {
                        DataFusionError::Plan(format!(
                            "multiplicity hint: key column missing: {name}"
                        ))
                    })
                })
                .collect::<DataFusionResult<Vec<_>>>()?;
            Ok(converter.convert_columns(&columns)?)
        })
        .collect()
}

fn build_hint_from_values(multiplicities: Vec<u64>, active: Vec<bool>) -> DataFusionResult<HintDF> {
    assert_eq!(
        multiplicities.len(),
        active.len(),
        "multiplicity hint: values/active length mismatch"
    );
    let row_count = multiplicities.len();
    // The multiplicity column must have the super table's domain, a one-row
    // domain included.
    let target = row_count.next_power_of_two();
    let pad = target - row_count;
    let mut m_vals = multiplicities;
    m_vals.extend(std::iter::repeat_n(0, pad));
    let mut a_vals = active;
    a_vals.extend(std::iter::repeat_n(false, pad));

    let multiplicity_field = Field::new("multiplicity", DataType::Int64, false);
    let activator_field = ACTIVATOR_FIELD.as_ref().clone();
    let row_id_field = Field::new(ROW_ID_COL_NAME, DataType::Int64, false);
    let schema = Arc::new(Schema::new(vec![
        multiplicity_field.clone(),
        activator_field.clone(),
        row_id_field.clone(),
    ]));

    let m_arr: ArrayRef = Arc::new(Int64Array::from_iter_values(
        m_vals.into_iter().map(|m| m as i64),
    ));
    let a_arr: ArrayRef = Arc::new(BooleanArray::from(a_vals));
    let r_arr: ArrayRef = Arc::new(Int64Array::from_iter_values((0..target).map(|i| i as i64)));

    let batch = RecordBatch::try_new(schema.clone(), vec![m_arr, a_arr, r_arr])?;
    let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
    let ctx = session_context();
    let df = ctx.read_table(Arc::new(mem_table))?;

    // Only `multiplicity` is materialized. Inactive super rows already carry
    // multiplicity 0, so an activator poly would be redundant.
    let multiplicity_fref: FieldRef = Arc::new(multiplicity_field);
    let activator_fref: FieldRef = Arc::new(activator_field);
    let row_id_fref: FieldRef = Arc::new(row_id_field);
    let mut should_materialize: IndexMap<FieldRef, bool> = IndexMap::new();
    should_materialize.insert(multiplicity_fref, true);
    should_materialize.insert(activator_fref, false);
    should_materialize.insert(row_id_fref, false);
    Ok(HintDF::new(df, should_materialize))
}
