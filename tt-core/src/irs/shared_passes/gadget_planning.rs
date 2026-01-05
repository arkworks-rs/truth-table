use crate::irs::{
    ir::LocalPass,
    nodes::{Node, NodeId},
    payloads::{EmptyPayload, HintDFPayload, PayloadStructure},
};
use ark_piop::SnarkBackend;

/// A planning pass that initializes the IR with hint DataFrames.
///
/// This pass converts an IR with empty payloads into an IR with Hint DataFrames.
pub struct GadgetPlanningPass<B>(std::marker::PhantomData<B>);

impl<B> GadgetPlanningPass<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<B> Default for GadgetPlanningPass<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> LocalPass<B, HintDFPayload, HintDFPayload> for GadgetPlanningPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PreOrder
    }
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        _payload: Option<&HintDFPayload>,
    ) -> Option<HintDFPayload> {
        match node {
            Node::Gadget(gadget_node) => Some(PayloadStructure::GadgetPayload(gadget_node.hints())),
            _ => None,
        }
    }
}
