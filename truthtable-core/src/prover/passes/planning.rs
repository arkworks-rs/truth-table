use ark_piop::SnarkBackend;
use datafusion::prelude::DataFrame;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{EmptyPayload, HintDFPayload, PayloadStructure},
};
use indexmap::IndexMap;

pub struct PlanningPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> PlanningPass<B> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B> Default for PlanningPass<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> LocalPass<B, EmptyPayload, HintDFPayload> for PlanningPass<B>
where
    B: SnarkBackend,
{
    fn transform(&self, node: &Node<B>, id: NodeId, _payload: &EmptyPayload) -> HintDFPayload {
        match node {
            Node::Plan(plan_node) => PayloadStructure::PlanPayload(plan_node.output().clone()),
            Node::Gadget(gadget_node) => PayloadStructure::GadgetPayload(gadget_node.hints()),
        }
    }
}
