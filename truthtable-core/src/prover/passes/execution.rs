use ark_piop::SnarkBackend;
use datafusion::{
    arrow::{datatypes::Schema, record_batch::RecordBatch},
    datasource::MemTable,
    prelude::DataFrame,
};

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{HintDFPayload, MemTablePayload, PayloadStructure},
};
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ExecutionPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> LocalPass<B, HintDFPayload, MemTablePayload> for ExecutionPass<B>
where
    B: SnarkBackend,
{
    fn transform(&self, _node: &Node<B>, id: NodeId, payload: &HintDFPayload) -> MemTablePayload {
        todo!()
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
