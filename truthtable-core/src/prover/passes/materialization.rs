use ark_piop::SnarkBackend;
use datafusion::{
    arrow::{datatypes::Schema, record_batch::RecordBatch},
    datasource::MemTable,
    prelude::DataFrame,
};
use datafusion_common::{DFSchema, DataFusionError};
use datafusion_expr::{Expr, col};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use tokio::runtime::RuntimeFlavor;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{HintDFPayload, MaterializedPayload, MaterializedTable, PayloadStructure},
};
use indexmap::IndexMap;
use std::sync::Arc;

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
    fn transform(
        &self,
        _node: &Node<B>,
        _id: NodeId,
        payload: Option<&HintDFPayload>,
    ) -> Option<MaterializedPayload> {
        match payload? {
            PayloadStructure::PlanPayload(hint_df) => {
                materialize_hint_df(hint_df).map(PayloadStructure::PlanPayload)
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

                Some(PayloadStructure::GadgetPayload(out))
            }
        }
    }
}

fn materialize_hint_df(hint_df: &crate::irs::nodes::hints::HintDF) -> Option<MaterializedTable> {
    let df = hint_df.data_frame().clone();
    // Build projection of columns marked for materialization
    let projection: Vec<Expr> = hint_df
        .field_materialization_iter()
        .filter(|&(_field, should_mat)| (*should_mat))
        .map(|(field, _should_mat)| col(field.name()))
        .collect();

    if projection.is_empty() {
        return None;
    }

    let df = df
        .select(projection)
        .expect("materialization projection should succeed");

    let batches = collect_blocking(df.clone()).expect("dataframe collection should succeed");
    let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();

    let df_schema_ref = df.schema();
    let arrow_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema_ref).clone();
    let mem_table =
        MemTable::try_new(Arc::new(arrow_schema), vec![batches]).expect("memtable creation");
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
