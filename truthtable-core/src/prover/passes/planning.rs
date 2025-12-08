use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{EmptyPayload, HintDFPayload, PayloadStructure},
};
use ark_piop::SnarkBackend;

/// A planning pass that initializes the prover IR with hint DataFrames
///
/// This pass converts an IR with empty payloads into an IR with Hint DataFrames.
pub struct PlanningPass<B>(std::marker::PhantomData<B>);

impl<B> PlanningPass<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
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
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        _payload: Option<&EmptyPayload>,
    ) -> Option<HintDFPayload> {
        match node {
            Node::Plan(plan_node) => {
                Some(PayloadStructure::PlanPayload(plan_node.output().clone()))
            }
            Node::Gadget(gadget_node) => Some(PayloadStructure::GadgetPayload(gadget_node.hints())),
        }
    }
}
