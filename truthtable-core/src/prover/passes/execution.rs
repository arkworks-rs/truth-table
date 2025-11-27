use ark_piop::SnarkBackend;
use datafusion::{
    arrow::{datatypes::Schema, record_batch::RecordBatch},
    datasource::MemTable,
    prelude::DataFrame,
};

use crate::{
    irs::{
        ir::LocalPass,
        nodes::id::NodeId,
        tree::{Node, PlanNode},
    },
    prover::payloads::{DataFramePayload, MemTablePayload, PayloadStructure},
};
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ExecutionPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> LocalPass<B, DataFramePayload, MemTablePayload> for ExecutionPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        _node: &dyn Node<B>,
        id: NodeId,
        payload: &DataFramePayload,
    ) -> MemTablePayload {
        match id {
            NodeId::PLAN(_) => match payload {
                PayloadStructure::PlanPayload(df) => {
                    let mem_table =
                        dataframe_to_memtable(df).expect("Failed to execute plan payload");
                    MemTablePayload::PlanPayload(mem_table)
                }
                PayloadStructure::GadgetPayload(_) => {
                    unreachable!("PLAN id must carry plan payload")
                }
            },
            NodeId::GADGET(_) => match payload {
                PayloadStructure::GadgetPayload(map) => {
                    let mut out = IndexMap::new();
                    for (name, df) in map.iter() {
                        let table =
                            dataframe_to_memtable(df).expect("Failed to execute gadget payload");
                        out.insert(name.clone(), table);
                    }
                    MemTablePayload::GadgetPayload(out)
                }
                PayloadStructure::PlanPayload(_) => {
                    unreachable!("GADGET id must carry gadget payload")
                }
            },
        }
    }
}

fn dataframe_to_memtable(df: &DataFrame) -> datafusion_common::Result<MemTable> {
    let batches = collect_blocking(df.clone())?;
    let schema = batches
        .get(0)
        .map(|b| b.schema())
        .unwrap_or_else(|| Arc::new(Schema::empty()));
    MemTable::try_new(schema, vec![batches])
}

fn collect_blocking(df: DataFrame) -> datafusion_common::Result<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(df.collect()),
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| datafusion_common::DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}
