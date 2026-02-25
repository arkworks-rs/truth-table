use crate::irs::{
    ir::LocalPass,
    nodes::{IsProverPlanNode, Node, NodeId},
    payloads::{EmptyPayload, HintDFPayload, PayloadStructure},
};
use ark_piop::SnarkBackend;

/// Prover-side planning pass that initializes hint DataFrames.
pub struct OutputPlanningPass<B>(std::marker::PhantomData<B>);

impl<B> OutputPlanningPass<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<B> Default for OutputPlanningPass<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> LocalPass<B, EmptyPayload, HintDFPayload> for OutputPlanningPass<B>
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
        _payload: Option<&EmptyPayload>,
    ) -> Option<HintDFPayload> {
        match node {
            Node::Plan(plan_node) => Some(PayloadStructure::PlanPayload(
                <crate::irs::nodes::PlanNode<B> as IsProverPlanNode<B>>::output(plan_node),
            )),
            Node::Gadget(_) => None,
        }
    }
    
    fn name(&self) -> &'static str {
        "Prover Output Planning"
    }
}
