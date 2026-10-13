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
use datafusion::arrow::{
    array::{Array, ArrayRef, BooleanArray, Int64Array},
    datatypes::{DataType, Field, FieldRef, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::DataFrame;
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use indexmap::IndexMap;
use std::collections::HashMap;

use crate::irs::nodes::hints::HintDF;

/// The multiplicity HintDF of a lookup gadget, from the plan-time super and
/// included HintDFs of an upstream gadget (typically `supp`). Collects both
/// eagerly and wraps the result in a MemTable-backed DataFrame.
///
/// Fails if an input DataFrame cannot be collected or if the two disagree
/// on the number of data columns.
pub fn build_multiplicity_hint(
    super_hint: &HintDF,
    included_hint: &HintDF,
) -> DataFusionResult<HintDF> {
    let super_df = super_hint.data_frame().clone();
    let included_df = included_hint.data_frame().clone();

    let super_data_cols = data_column_names(&super_df);
    let included_data_cols = data_column_names(&included_df);
    if super_data_cols.len() != included_data_cols.len() {
        return Err(DataFusionError::Plan(format!(
            "lookup multiplicity hint: super has {} data columns but included has {}",
            super_data_cols.len(),
            included_data_cols.len()
        )));
    }

    let super_batches = crate::session::block_on(super_df.clone().collect())?;
    let included_batches = crate::session::block_on(included_df.clone().collect())?;

    let super_active = active_mask_from_batches(&super_batches);
    let included_active = active_mask_from_batches(&included_batches);
    let super_keys = key_tuples_from_batches(&super_batches, &super_data_cols)?;
    let included_keys = key_tuples_from_batches(&included_batches, &included_data_cols)?;

    // Same result as `expected_lookup_multiplicities_from_values`, but over
    // ScalarValue tuples: at plan time the values are not field elements.
    let mut included_counts: HashMap<Vec<ScalarValue>, i64> = HashMap::new();
    for (row, active) in included_active.iter().enumerate() {
        if *active {
            *included_counts
                .entry(included_keys[row].clone())
                .or_insert(0) += 1;
        }
    }
    let mut seen_active_super: HashMap<Vec<ScalarValue>, ()> = HashMap::new();
    let mut multiplicities: Vec<i64> = vec![0; super_active.len()];
    for row in 0..super_active.len() {
        if !super_active[row] {
            continue;
        }
        let key = super_keys[row].clone();
        if seen_active_super.insert(key.clone(), ()).is_none() {
            multiplicities[row] = included_counts.get(&key).copied().unwrap_or(0);
        }
    }

    build_hint_from_values(multiplicities, super_active)
}

/// Schema-matching HintDF for the verifier side. Verifier planning must not
/// collect DataFrames, and the tracking pass only reads the schema and the
/// `should_materialize` flags, so the data is a one-row placeholder.
pub fn build_multiplicity_hint_schema_only(_super_hint: &HintDF) -> DataFusionResult<HintDF> {
    build_hint_from_values(vec![0], vec![false])
}

fn data_column_names(df: &DataFrame) -> Vec<String> {
    df.schema()
        .fields()
        .iter()
        .filter_map(|field| (!is_system_column(field.name())).then_some(field.name().to_string()))
        .collect()
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

fn key_tuples_from_batches(
    batches: &[RecordBatch],
    key_cols: &[String],
) -> DataFusionResult<Vec<Vec<ScalarValue>>> {
    let mut out = Vec::new();
    for batch in batches {
        let key_indices: Vec<usize> = key_cols
            .iter()
            .map(|name| batch.schema().index_of(name))
            .collect::<Result<_, _>>()
            .map_err(|e| {
                DataFusionError::Plan(format!("multiplicity hint: key column missing: {e}"))
            })?;
        for row in 0..batch.num_rows() {
            let tuple = key_indices
                .iter()
                .map(|idx| ScalarValue::try_from_array(batch.column(*idx), row))
                .collect::<DataFusionResult<Vec<_>>>()?;
            out.push(tuple);
        }
    }
    Ok(out)
}

fn build_hint_from_values(multiplicities: Vec<i64>, active: Vec<bool>) -> DataFusionResult<HintDF> {
    assert_eq!(
        multiplicities.len(),
        active.len(),
        "multiplicity hint: values/active length mismatch"
    );
    let row_count = multiplicities.len();
    // Pad to a power-of-two so downstream MLE construction has a clean domain.
    let target = if row_count <= 1 {
        2
    } else {
        row_count.next_power_of_two()
    };
    let pad = target - row_count;
    let mut m_vals = multiplicities;
    m_vals.extend(std::iter::repeat_n(0i64, pad));
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

    let m_arr: ArrayRef = Arc::new(Int64Array::from(m_vals));
    let a_arr: ArrayRef = Arc::new(BooleanArray::from(a_vals));
    let r_arr: ArrayRef = Arc::new(Int64Array::from_iter_values((0..target).map(|i| i as i64)));

    let batch = RecordBatch::try_new(schema.clone(), vec![m_arr, a_arr, r_arr])?;
    let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
    let ctx = session_context();
    let df = ctx.read_table(Arc::new(mem_table))?;

    // Only `multiplicity` is materialized. Inactive super rows already carry
    // multiplicity 0 (the `!super_active[row]` skip in
    // `build_multiplicity_hint`), so an activator poly would be redundant.
    let multiplicity_fref: FieldRef = Arc::new(multiplicity_field);
    let activator_fref: FieldRef = Arc::new(activator_field);
    let row_id_fref: FieldRef = Arc::new(row_id_field);
    let mut should_materialize: IndexMap<FieldRef, bool> = IndexMap::new();
    should_materialize.insert(multiplicity_fref, true);
    should_materialize.insert(activator_fref, false);
    should_materialize.insert(row_id_fref, false);
    Ok(HintDF::new(df, should_materialize))
}
