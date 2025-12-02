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

pub struct MaterializationPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}
impl<B> MaterializationPass<B> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
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
        payload: &HintDFPayload,
    ) -> MaterializedPayload {
        match payload {
            PayloadStructure::PlanPayload(hint_df) => {
                PayloadStructure::PlanPayload(materialize_hint_df(hint_df))
            }
            PayloadStructure::GadgetPayload(map) => {
                #[cfg(feature = "parallel")]
                let out: IndexMap<_, _> = map
                    .par_iter()
                    .map(|(k, hint_df)| (k.clone(), materialize_hint_df(hint_df)))
                    .collect();

                #[cfg(not(feature = "parallel"))]
                let out: IndexMap<_, _> = map
                    .iter()
                    .map(|(k, hint_df)| (k.clone(), materialize_hint_df(hint_df)))
                    .collect();

                PayloadStructure::GadgetPayload(out)
            }
        }
    }
}

fn materialize_hint_df(hint_df: &crate::irs::nodes::hints::HintDF) -> MaterializedTable {
    let df = hint_df.data_frame().clone();
    // Build projection of columns marked for materialization
    let projection: Vec<Expr> = hint_df
        .field_materialization_iter()
        .filter(|&(_field, should_mat)| (*should_mat))
        .map(|(field, _should_mat)| col(field.name()))
        .collect();

    if projection.is_empty() {
        let empty_mem =
            MemTable::try_new(Arc::new(Schema::empty()), vec![vec![]]).expect("empty memtable");
        return MaterializedTable::new(empty_mem, Vec::new(), 0);
    }

    let df = df
        .select(projection)
        .expect("materialization projection should succeed");

    let col_names: Vec<String> = df
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().to_string())
        .collect();

    let batches = collect_blocking(df.clone()).expect("dataframe collection should succeed");
    let row_count: usize = batches.iter().map(|b| b.num_rows()).sum();

    let df_schema_ref = df.schema();
    let arrow_schema: Schema = <DFSchema as AsRef<Schema>>::as_ref(df_schema_ref).clone();
    let mem_table = dataframe_to_memtable_from_batches(batches, Arc::new(arrow_schema));
    MaterializedTable::new(mem_table, col_names, row_count)
}

fn dataframe_to_memtable_from_batches(batches: Vec<RecordBatch>, schema: Arc<Schema>) -> MemTable {
    MemTable::try_new(schema, vec![batches])
        .expect("dataframe materialization memtable creation should succeed")
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
