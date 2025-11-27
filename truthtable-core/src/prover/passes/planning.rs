use ark_piop::SnarkBackend;
use datafusion::{
    arrow::{datatypes::Schema, record_batch::RecordBatch},
    datasource::MemTable,
    prelude::DataFrame,
};
use futures::io::Empty;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::id::NodeId,
        tree::{Gadget, Node, PlanNode},
    },
    prover::payloads::{DataFramePayload, EmptyPayload, PayloadStructure},
};
use indexmap::IndexMap;
use std::sync::Arc;

pub struct PlanningPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> LocalPass<B, EmptyPayload, DataFramePayload> for PlanningPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &dyn Node<B>,
        id: NodeId,
        _payload: &EmptyPayload,
    ) -> DataFramePayload {
        match id {
            NodeId::PLAN(_) => {
                let plan_node = node.as_plan_node().expect("Expected plan node for PLAN id");
                let df = plan_node.output().data_frame().clone();
                PayloadStructure::PlanPayload(df)
            }
            NodeId::GADGET(_) => {
                let gadget = node
                    .as_gadget_node()
                    .expect("Expected gadget node for GADGET id");
                let dfs: IndexMap<String, DataFrame> = gadget
                    .hints()
                    .into_iter()
                    .map(|(name, hint)| (name, hint.data_frame().clone()))
                    .collect();
                PayloadStructure::GadgetPayload(dfs)
            }
        }
    }
}
