use crate::irs::{
    ir::LocalPass,
    nodes::{
        hints::{begin_schema_only_ctx_scope, end_schema_only_ctx_scope},
        IsVerifierPlanNode, Node, NodeId, begin_verifier_output_cache_scope,
        end_verifier_output_cache_scope,
    },
    payloads::{EmptyPayload, HintDFDFPayload, HintDFPayload, PayloadStructure},
};
use ark_piop::SnarkBackend;

/// Verifier-side planning pass that initializes hint DataFrames.
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

impl<B> LocalPass<B, EmptyPayload, HintDFDFPayload> for OutputPlanningPass<B>
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
    ) -> Option<HintDFDFPayload> {
        match node {
            Node::Plan(plan_node) => {
                Some(PayloadStructure::PlanPayload(<crate::irs::nodes::PlanNode<
                    B,
                > as IsVerifierPlanNode<B>>::output(
                    plan_node
                )))
            }
            Node::Gadget(_) => None,
        }
    }

    fn begin_pass(&self, _ir: &crate::irs::ir::Ir<B, EmptyPayload>) {
        begin_schema_only_ctx_scope();
        begin_verifier_output_cache_scope();
    }

    fn end_pass(&self) {
        end_verifier_output_cache_scope();
        end_schema_only_ctx_scope();
    }

    fn name(&self) -> &'static str {
        "Verifier Output Planning"
    }
}
