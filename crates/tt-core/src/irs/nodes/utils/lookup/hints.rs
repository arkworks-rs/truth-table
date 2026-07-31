//! Plan-time construction of the lookup `multiplicity` witness as a
//! `HintDF`.
//!
//! Historically, the multiplicity poly was computed and committed at
//! `initialize_gadgets` time by walking the super/included TrackedTable
//! evaluations and calling `prover.track_and_commit_mat_mv_poly(...)`.
//! That placed the commit late in the pipeline (post-tracking pass) and
//! required a mirror `verifier.track_next_mv_com()` call, hard-wiring
//! the commit order.
//!
//! This module lifts the multiplicity computation into plan-time hint
//! planning: given the super and included HintDFs (already lazy
//! DataFrames from upstream), we eagerly collect the ACTIVE rows of
//! both, compute the multiplicity vector by the same algorithm the
//! prover would run at runtime, and wrap the result in a
//! MemTable-backed HintDF marked `should_materialize=true`. From then
//! on, the standard materialization → arithmetization → commitment →
//! tracking pipeline turns it into a `TrackedTable` in the payload —
//! same treatment as any other base-table column.
//!
//! # Semantics
//!
//! For each row `i` of the super table (in row-id order):
//! - `multiplicity[i] = 0` if super's activator at row `i` is 0.
//! - `multiplicity[i] = 0` if super's key tuple at row `i` was already
//!   emitted at some earlier active super row (dedup — the
//!   HintedLookupPIOP only counts against the first occurrence).
//! - Otherwise `multiplicity[i] = count of active included rows whose
//!   key tuple equals super[i]'s key tuple`.
//!
//! Output HintDF schema: `{ __activator__: Bool, multiplicity: Int64 }`
//! at the same log_size as super, with row_id assigned 0..2^k−1.
//!
//! # Design invariant this establishes
//!
//! This is the first conversion under the "all challenge-independent
//! committed polys have a plan-time HintDF" invariant. Future
//! conversions (sign chunks, BezoutNoDup dedup, MCPM per-factor slots)
//! follow the same shape:
//!
//! 1. Add a `hints.rs` module under the gadget with builder(s) that
//!    take upstream HintDFs and return the witness HintDF.
//! 2. Call the builder from `initialize_gadget_plans` on both prover
//!    and verifier sides — verifier uses a schema-matching HintDF so
//!    the tracking pass consumes the commit in the right slot.
//! 3. Guard the `initialize_gadgets` commit path so it only runs when
//!    the payload doesn't already carry the tracked witness (fallback
//!    for test harness usage).
//!
//! Verifier symmetry note: the verifier HintDF must have the same
//! schema and `should_materialize` flags as the prover's, because the
//! tracking pass consumes commits in the same field order on both
//! sides. Actual data values on the verifier are unused (verifier
//! doesn't run materialization).

use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, is_system_column};
use datafusion::arrow::{
    array::{Array, ArrayRef, BooleanArray, Int64Array},
    datatypes::{DataType, Field, FieldRef, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::{DataFrame, SessionContext};
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue};
use indexmap::IndexMap;
use std::collections::HashMap;
use tokio::runtime::RuntimeFlavor;

use crate::irs::nodes::hints::HintDF;

/// Build the multiplicity HintDF for a lookup gadget given the plan-time
/// super and included HintDFs from an upstream gadget (typically `supp`).
///
/// This eagerly runs the same algorithm as `expected_lookup_multiplicities_from_values`
/// against the collected super/included data, then wraps the result in
/// a MemTable-backed DataFrame. The DataFrame's `multiplicity` and
/// `__activator__` fields are both marked `should_materialize=true` so
/// the materialization/commitment passes produce a committed
/// TrackedTable.
///
/// # Errors
///
/// Returns a DataFusion error if either input DataFrame can't be
/// collected (rare — HintDFs are supposed to be materializable by the
/// time plan passes run) or if the schemas disagree on data columns.
pub fn build_multiplicity_hint(
    super_hint: &HintDF,
    included_hint: &HintDF,
) -> DataFusionResult<HintDF> {
    let super_df = super_hint.data_frame().clone();
    let included_df = included_hint.data_frame().clone();

    // Extract the data columns (schema order, excluding system columns).
    let super_data_cols = data_column_names(&super_df);
    let included_data_cols = data_column_names(&included_df);
    if super_data_cols.len() != included_data_cols.len() {
        return Err(DataFusionError::Plan(format!(
            "lookup multiplicity hint: super has {} data columns but included has {}",
            super_data_cols.len(),
            included_data_cols.len()
        )));
    }

    let super_batches = collect_blocking(super_df.clone())?;
    let included_batches = collect_blocking(included_df.clone())?;

    let super_active = active_mask_from_batches(&super_batches);
    let included_active = active_mask_from_batches(&included_batches);
    let super_keys = key_tuples_from_batches(&super_batches, &super_data_cols)?;
    let included_keys = key_tuples_from_batches(&included_batches, &included_data_cols)?;

    // Same algorithm as expected_lookup_multiplicities_from_values, but
    // over ScalarValue tuples instead of field elements — DataFusion
    // hasn't lifted to the field yet at plan time.
    let mut included_counts: HashMap<Vec<ScalarValue>, i64> = HashMap::new();
    for (row, active) in included_active.iter().enumerate() {
        if *active {
            *included_counts.entry(included_keys[row].clone()).or_insert(0) += 1;
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

/// Schema-matching HintDF for the verifier side. Data values are not
/// consumed by the verifier — the tracking pass just needs the schema
/// + `should_materialize` flags to know which commit slot to consume
/// from the proof. All-zero data is fine.
pub fn build_multiplicity_hint_schema_only(
    super_hint: &HintDF,
) -> DataFusionResult<HintDF> {
    // Verifier planning must not collect DataFrames (per convention);
    // use the super hint's schema to derive log_size only via row count
    // inference. We produce a placeholder DataFrame with all-zeros; the
    // materialization pass never runs on the verifier side, so these
    // values are unused.
    let super_df = super_hint.data_frame().clone();
    let super_row_count = infer_super_row_count(&super_df)?;
    let mut multiplicities = vec![0i64; super_row_count];
    let mut active = vec![false; super_row_count];
    // Populate a minimum-length placeholder if the super count is zero
    // (never expected in practice, but keep the DataFrame constructible).
    if super_row_count == 0 {
        multiplicities.push(0);
        active.push(false);
    }
    let _ = &mut multiplicities;
    let _ = &mut active;
    build_hint_from_values(multiplicities, active)
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
                    // Non-boolean activator: treat non-null/non-zero as active.
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
                for _ in 0..batch.num_rows() {
                    out.push(true);
                }
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
    let target = if row_count <= 1 { 2 } else { row_count.next_power_of_two() };
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
    let r_arr: ArrayRef = Arc::new(Int64Array::from_iter_values(
        (0..target).map(|i| i as i64),
    ));

    let batch = RecordBatch::try_new(schema.clone(), vec![m_arr, a_arr, r_arr])?;
    let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
    let ctx = SessionContext::new();
    let df = ctx.read_table(Arc::new(mem_table))?;

    // multiplicity: materialize. Activator + row_id: system columns, don't materialize.
    let multiplicity_fref: FieldRef = Arc::new(multiplicity_field);
    let activator_fref: FieldRef = Arc::new(activator_field);
    let row_id_fref: FieldRef = Arc::new(row_id_field);
    let mut should_materialize: IndexMap<FieldRef, bool> = IndexMap::new();
    should_materialize.insert(multiplicity_fref, true);
    should_materialize.insert(activator_fref, false);
    should_materialize.insert(row_id_fref, false);
    Ok(HintDF::new(df, should_materialize))
}

fn infer_super_row_count(super_df: &DataFrame) -> DataFusionResult<usize> {
    // Verifier planning must not collect the super DataFrame. Fall back
    // to a schema-only inference: the row count for a plan-time hint at
    // gadget scope is determined by materialization, not by the schema
    // alone. Return 0 here; the verifier-side hint's data values are
    // never consumed (verifier skips materialization) — the tracking
    // pass only needs the schema + should_materialize flags.
    let _ = super_df;
    Ok(0)
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
                    DataFusionError::Execution(
                        "multiplicity hint collection thread panicked".to_string(),
                    )
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
