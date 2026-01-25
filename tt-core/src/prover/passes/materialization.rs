use crate::irs::nodes::IsNode;
use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::{HintDFPayload, PayloadStructure},
    },
    prover::payloads::{MaterializedPayload, MaterializedTable},
};
use ark_piop::SnarkBackend;
use datafusion::catalog::TableProvider;
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray, Int64Array},
        compute::{concat, concat_batches},
        datatypes::{FieldRef, Schema},
        record_batch::{RecordBatch, RecordBatchOptions},
    },
    datasource::MemTable,
    prelude::DataFrame,
};
use datafusion_common::{Column, DFSchema, DataFusionError, ScalarValue};
use datafusion_expr::Expr;
use indexmap::IndexMap;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::sync::Arc;
use tokio::runtime::RuntimeFlavor;

/// A materialization pass that materializes the prover's hint DataFrames
///
/// This pass converts an IR with Hint DataFrame payloads into an IR with materialized in-memory tables.
pub struct MaterializationPass<B>(std::marker::PhantomData<B>);
impl<B> MaterializationPass<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<B> Default for MaterializationPass<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> LocalPass<B, HintDFPayload, MaterializedPayload> for MaterializationPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        payload: Option<&HintDFPayload>,
    ) -> Option<MaterializedPayload> {
        let Some(payload) = payload else {
            tracing::debug!(node = %node.name(),  "skipped (no payload)");
            return None;
        };
        match payload {
            PayloadStructure::PlanPayload(hint_df) => {
                let materialized = materialize_hint_df(hint_df);
                tracing::debug!( node = %node.name(), typ= "plan", num_cols= materialized.as_ref().map_or(0, |m| m.mem_table().schema().fields().len()), num_rows= materialized.as_ref().map_or(0, |m| m.row_count()), "materialized");
                materialized.map(PayloadStructure::PlanPayload)
            }
            PayloadStructure::GadgetPayload(map) => {
                #[cfg(feature = "parallel")]
                let out: IndexMap<_, _> = map
                    .par_iter()
                    .filter_map(|(k, hint_df)| {
                        materialize_hint_df(hint_df).map(|mat| (k.clone(), mat))
                    })
                    .collect();

                #[cfg(not(feature = "parallel"))]
                let out: IndexMap<_, _> = map
                    .iter()
                    .filter_map(|(k, hint_df)| {
                        materialize_hint_df(hint_df).map(|mat| (k.clone(), mat))
                    })
                    .collect();

                out.iter()
                    .for_each(|(k, v)| tracing::debug!( node = %node.name(),typ= "gadget",  key=%k, num_cols = v.mem_table().schema().fields().len(), num_rows= v.row_count(), "materialized"));

                Some(PayloadStructure::GadgetPayload(out))
            }
        }
    }
}

fn materialize_hint_df(hint_df: &crate::irs::nodes::hints::HintDF) -> Option<MaterializedTable> {
    let df = hint_df.data_frame().clone();
    let df_schema = df.schema();
    // Build projection of columns marked for materialization, preserving qualifiers
    // to avoid `FieldNotFound` errors when the schema uses table-qualified columns.
    let projection: Vec<Expr> = hint_df
        .field_materialization_iter()
        .filter(|&(_field, should_mat)| *should_mat)
        .map(|(field, _should_mat)| projection_expr_for_field(df_schema, field))
        .collect();

    let df = df
        .select(projection)
        .expect("materialization projection should succeed");

    let batches = collect_blocking(df.clone()).expect("dataframe collection should succeed");

    let df_schema_ref = df.schema();
    let arrow_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema_ref).clone();
    let (batches, row_count) =
        pad_batches_to_power_of_two(&arrow_schema, batches).expect("padding should succeed");

    let constraints = hint_df
        .constraints()
        .cloned()
        .or_else(|| crate::irs::nodes::hints::infer_constraints_from_plan(df.logical_plan()));
    let mut mem_table =
        MemTable::try_new(Arc::new(arrow_schema), vec![batches]).expect("memtable creation");
    if let Some(constraints) = constraints {
        mem_table = mem_table.with_constraints(constraints);
    }
    Some(MaterializedTable::new(mem_table, row_count))
}

fn collect_blocking(df: DataFrame) -> datafusion_common::Result<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            RuntimeFlavor::CurrentThread => {
                // Spawn a dedicated thread with its own runtime to avoid blocking a single-thread runtime.
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

fn pad_batches_to_power_of_two(
    schema: &Schema,
    batches: Vec<RecordBatch>,
) -> datafusion_common::Result<(Vec<RecordBatch>, usize)> {
    let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();
    if row_count == 0 {
        let target = 2;
        let schema_ref = Arc::new(schema.clone());
        if schema_ref.fields().is_empty() {
            let options = RecordBatchOptions::new().with_row_count(Some(target));
            let out_batch = RecordBatch::try_new_with_options(schema_ref, vec![], &options)?;
            return Ok((vec![out_batch], target));
        }

        let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
        for field in schema_ref.fields().iter() {
            let padded = if field.name() == arithmetic::ACTIVATOR_COL_NAME {
                Arc::new(BooleanArray::from(vec![false; target])) as ArrayRef
            } else if field.name() == arithmetic::ROW_ID_COL_NAME {
                let vals: Vec<i64> = (0..target as i64).collect();
                Arc::new(Int64Array::from(vals)) as ArrayRef
            } else {
                let null = ScalarValue::try_new_null(field.data_type())?;
                null.to_array_of_size(target)?
            };
            output_arrays.push(padded);
        }

        let out_batch = RecordBatch::try_new(schema_ref, output_arrays)?;
        return Ok((vec![out_batch], target));
    }
    let target = row_count.next_power_of_two();
    let pad = target - row_count;
    if pad == 0 {
        return Ok((batches, row_count));
    }

    let schema_ref = Arc::new(schema.clone());
    if schema_ref.fields().is_empty() {
        // Arrow requires an explicit row count when constructing a zero-column batch.
        let options = RecordBatchOptions::new().with_row_count(Some(target));
        let out_batch = RecordBatch::try_new_with_options(schema_ref, vec![], &options)?;
        return Ok((vec![out_batch], target));
    }
    let combined = if batches.is_empty() {
        None
    } else {
        let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
        Some(concat_batches(&schema_ref, batch_refs)?)
    };

    let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
    for (idx, field) in schema_ref.fields().iter().enumerate() {
        let padded = if field.name() == arithmetic::ACTIVATOR_COL_NAME {
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| Arc::new(BooleanArray::from(Vec::<bool>::new())) as ArrayRef);
            let pad_arr: ArrayRef = Arc::new(BooleanArray::from(vec![false; pad]));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if let Some(batch) = combined.as_ref() {
            let base = batch.column(idx).clone();
            let last = ScalarValue::try_from_array(base.as_ref(), row_count - 1)?;
            let pad_arr = last.to_array_of_size(pad)?;
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else {
            let null = ScalarValue::try_new_null(field.data_type())?;
            null.to_array_of_size(pad)?
        };
        output_arrays.push(padded);
    }

    let out_batch = RecordBatch::try_new(schema_ref, output_arrays)?;
    Ok((vec![out_batch], target))
}

fn projection_expr_for_field(schema: &DFSchema, field: &FieldRef) -> Expr {
    let name = field.name();
    if let Some((qualifier, _)) = schema.iter().find(|(_, f)| f.name() == name) {
        return Expr::Column(Column::new(qualifier.cloned(), name));
    }
    if let Some((relation, col_name)) = name.split_once('.')
        && let Some((qualifier, _)) = schema.iter().find(|(q, f)| {
            f.name() == col_name && q.map(|q| q.to_string()) == Some(relation.to_string())
        })
    {
        return Expr::Column(Column::new(qualifier.cloned(), col_name));
    }
    Expr::Column(Column::new_unqualified(name))
}
