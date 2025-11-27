mod round;
#[cfg(test)]
mod tests;
use std::marker::PhantomData;
// keep single Arc import (already pulled in above).

use crate::nodes::{hints::HintDF, prover::ProverGadget};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, BooleanBuilder},
    compute,
    datatypes::{DataType, Field, Schema, SchemaRef},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::{DataFrame, SessionContext};
use datafusion_common::ScalarValue;
use indexmap::IndexMap;
use std::sync::Arc;

pub const NAME: &str = "Contigous_Sort_Gadget";
pub const INPUT_DATA_FRAME_KEY: &str = "__Contigous_Sort__input_data_frame__";
pub const SORTED_DATA_FRAME_KEY: &str = "__Contigous_Sort__sorted_data_frame__";
pub const SHIFTED_DATA_FRAME_KEY: &str = "__Contigous_Sort__shifted_data_frame__";
pub const TIE_DATA_FRAME_KEY: &str = "__Contigous_Sort__tie_data_frame__";
#[derive(Clone)]
pub struct Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<B> ProverGadget<B> for Prover<B>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF> {
        let input_df = input
            .get(INPUT_DATA_FRAME_KEY)
            .expect("contiguous sort gadget requires input df")
            .data_frame()
            .clone();

        let shifted_df = shift_dataframe(&input_df);
        let tie_df = build_tie_dataframe(&input_df);

        let mut result = IndexMap::new();
        result.insert(
            SHIFTED_DATA_FRAME_KEY.to_string(),
            HintDF::new_virtual(shifted_df),
        );
        result.insert(TIE_DATA_FRAME_KEY.to_string(), HintDF::new_virtual(tie_df));
        result
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<B>>> {
        todo!()
    }

    fn name(&self) -> String {
        NAME.to_string()
    }
}

/// Shift the dataframe up by one row: row i becomes row i+1 from the original.
fn shift_dataframe(df: &DataFrame) -> DataFrame {
    let collected = futures::executor::block_on(df.clone().collect())
        .expect("collecting input dataframe for shift should succeed");
    let arrow_schema: SchemaRef = collected
        .first()
        .map(|b| b.schema())
        .unwrap_or_else(|| Arc::new(Schema::new(Vec::<Field>::new())));

    let batch = compute::concat_batches(&arrow_schema, &collected)
        .expect("concatenating batches for shift should succeed");
    let row_count = batch.num_rows();
    if row_count == 0 {
        let mem_table =
            MemTable::try_new(arrow_schema.clone(), vec![vec![batch]]).expect("empty memtable");
        let ctx = SessionContext::new();
        return ctx
            .read_table(Arc::new(mem_table))
            .expect("empty shift dataframe should succeed");
    }

    let mut shifted_arrays: Vec<ArrayRef> = Vec::with_capacity(batch.num_columns());
    for col in batch.columns() {
        // Shift circularly: rows 1..end move up, row 0 goes to the last position.
        let prefix = col.slice(1, row_count.saturating_sub(1));
        let last = col.slice(0, 1);
        let shifted = compute::concat(&[prefix.as_ref(), last.as_ref()])
            .expect("concat slices for shift should succeed");
        shifted_arrays.push(shifted);
    }

    let shifted_batch = RecordBatch::try_new(arrow_schema.clone(), shifted_arrays)
        .expect("building shifted batch failed");
    let mem_table = MemTable::try_new(arrow_schema.clone(), vec![vec![shifted_batch]])
        .expect("building shifted memtable failed");
    let ctx = SessionContext::new();
    ctx.read_table(Arc::new(mem_table))
        .expect("building shifted dataframe should succeed")
}

/// Build a boolean dataframe indicating prefix ties with the next row.
fn build_tie_dataframe(df: &DataFrame) -> DataFrame {
    // Collect to batches synchronously (hint computation).
    let collected = futures::executor::block_on(df.clone().collect())
        .expect("collecting input dataframe for tie computation should succeed");
    let arrow_schema: SchemaRef = collected
        .get(0)
        .map(|b| b.schema())
        .unwrap_or_else(|| Arc::new(Schema::new(Vec::<Field>::new())));

    // Concatenate all batches into a single batch to simplify row-wise computation.
    let batch = compute::concat_batches(&arrow_schema, &collected)
        .expect("concatenating batches for tie computation should succeed");
    let row_count = batch.num_rows();

    let mut tie_arrays: Vec<ArrayRef> = Vec::new();
    let mut tie_fields: Vec<Field> = Vec::new();

    // We emit tie columns for prefixes up to the penultimate column (n-1 ties for n columns).
    for col_idx in 0..batch.num_columns().saturating_sub(1) {
        let mut col_ties = BooleanBuilder::with_capacity(row_count);
        let mut prefix_eq: Option<BooleanArray> = None;

        for prefix_idx in 0..=col_idx {
            let col = batch.column(prefix_idx);
            if row_count == 0 {
                prefix_eq = Some(BooleanArray::from(Vec::<bool>::new()));
                break;
            }
            let lhs = col.slice(0, row_count.saturating_sub(1));
            let rhs = col.slice(1, row_count.saturating_sub(1));
            let eq = elementwise_eq(&lhs, &rhs);
            prefix_eq = match prefix_eq {
                None => Some(eq),
                Some(current) => {
                    Some(compute::and(&current, &eq).expect("boolean conjunction should succeed"))
                }
            };
        }

        let prefix_eq = prefix_eq.unwrap_or_else(|| BooleanArray::from(Vec::<bool>::new()));
        // Fill rows except the last with computed values; last row has no successor so mark false.
        for i in 0..row_count {
            let val = if i + 1 < row_count {
                prefix_eq.value(i)
            } else {
                false
            };
            col_ties.append_value(val);
        }

        tie_arrays.push(Arc::new(col_ties.finish()) as ArrayRef);
        tie_fields.push(Field::new(
            format!("tie_{}", col_idx + 1),
            DataType::Boolean,
            false,
        ));
    }

    let tie_schema = Arc::new(Schema::new(tie_fields));
    let tie_batch =
        RecordBatch::try_new(tie_schema.clone(), tie_arrays).expect("building tie batch failed");
    let mem_table = MemTable::try_new(tie_schema.clone(), vec![vec![tie_batch]])
        .expect("building tie memtable failed");
    let ctx = SessionContext::new();
    ctx.read_table(Arc::new(mem_table))
        .expect("building tie dataframe should succeed")
}

fn elementwise_eq(lhs: &ArrayRef, rhs: &ArrayRef) -> BooleanArray {
    let len = lhs.len().min(rhs.len());
    let mut builder = BooleanBuilder::with_capacity(len);
    for i in 0..len {
        let l = ScalarValue::try_from_array(lhs, i).expect("lhs scalar extraction");
        let r = ScalarValue::try_from_array(rhs, i).expect("rhs scalar extraction");
        builder.append_value(l == r);
    }
    builder.finish()
}
