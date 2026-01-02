use arithmetic::table::ArithTable;
use ark_ff::PrimeField;
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::compute::concat_batches;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use indexmap::IndexMap;
use std::sync::Arc;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{ArithPayload, MaterializedPayload, MaterializedTable},
};
/// An arithmetization pass that arithmetizes the prover's materialized in-memory tables
///
/// This pass converts an IR with materialized in-memory tables into an IR with arithmetized tables, meaning that each column is encoded and represented as multilinear extensions (MLEs) over a finite field.
pub struct ArithmetizationPass<B>(std::marker::PhantomData<B>);

impl<B> ArithmetizationPass<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<B> Default for ArithmetizationPass<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> LocalPass<B, MaterializedPayload, ArithPayload<B::F>> for ArithmetizationPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        _node: &Node<B>,
        _id: NodeId,
        payload: Option<&MaterializedPayload>,
    ) -> Option<ArithPayload<B::F>> {
        match payload? {
            MaterializedPayload::PlanPayload(mat) => Some(ArithPayload::PlanPayload(
                arithmetize_materialized_table(mat),
            )),
            MaterializedPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (k, mat) in map {
                    out.insert(k.clone(), arithmetize_materialized_table(mat));
                }
                Some(ArithPayload::GadgetPayload(out))
            }
        }
    }
}

fn arithmetize_materialized_table<F: PrimeField>(mat: &MaterializedTable) -> ArithTable<F> {
    let batches = mat
        .batches()
        .expect("failed to read batches from materialized table");
    if batches.is_empty() {
        return ArithTable::new(None, IndexMap::new(), 0);
    }

    let schema_ref = batches[0].schema();
    let batch_refs: Vec<&datafusion::arrow::record_batch::RecordBatch> = batches.iter().collect();
    let combined_batch = concat_batches(&schema_ref, batch_refs)
        .expect("failed to concatenate record batches for arithmetization");

    let total_rows = combined_batch.num_rows();
    assert!(
        total_rows.is_power_of_two(),
        "Arithmetized tables must have power-of-two number of rows, got {}",
        total_rows
    );
    let log_vars = total_rows.trailing_zeros() as usize;
    let num_total_cols = schema_ref.fields().len();

    let encoded_columns: Vec<Vec<(FieldRef, Vec<F>)>> = (0..num_total_cols)
        .map(|col_idx| {
            let base_field = schema_ref.fields()[col_idx].clone();
            let encoded = arithmetic::encoding::encode_arrow_array_to_field::<F>(
                combined_batch.column(col_idx),
            )
            .expect("arrow encoding should succeed");
            let mut segmented = Vec::with_capacity(encoded.len());
            for (segment_idx, values) in encoded.into_iter().enumerate() {
                let field_ref = if segment_idx == 0 {
                    base_field.clone()
                } else {
                    Arc::new(Field::new(
                        format!("{}__enc{}", base_field.name(), segment_idx),
                        base_field.data_type().clone(),
                        base_field.is_nullable(),
                    ))
                };
                segmented.push((field_ref, values));
            }
            segmented
        })
        .collect();

    let mut flattened_fields: Vec<FieldRef> = Vec::new();
    let mut flattened_values: Vec<(FieldRef, Vec<F>)> = Vec::new();
    for column_group in encoded_columns {
        for (field_ref, values) in column_group {
            flattened_fields.push(field_ref.clone());
            flattened_values.push((field_ref, values));
        }
    }

    let tracked_polys: IndexMap<FieldRef, Arc<MLE<F>>> = flattened_values
        .into_iter()
        .map(|(field_ref, values)| {
            let mle = Arc::new(MLE::from_evaluations_slice(log_vars, &values));
            (field_ref, mle)
        })
        .collect();

    let schema_fields: Vec<Field> = flattened_fields
        .iter()
        .map(|field_ref| field_ref.as_ref().clone())
        .collect();
    let schema = Some(Schema::new(schema_fields));

    ArithTable::new(schema, tracked_polys, log_vars)
}
