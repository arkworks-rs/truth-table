use std::cell::RefCell;

use crate::irs::{
    ir::LocalPass,
    nodes::{Node, NodeId, ProverNodeOps},
    payloads::{HintDFPayload, PayloadStructure},
    shared_ir::OutputPlannedIr,
};
use ark_piop::SnarkBackend;

/// Prover-side gadget planning pass.
///
/// This pass executes pre-order and lets each node update prover planning hints.
pub struct GadgetPlanningPass<B: SnarkBackend> {
    planned_ir: RefCell<OutputPlannedIr<B>>,
}

impl<B: SnarkBackend> GadgetPlanningPass<B> {
    pub fn new(planned_ir: &OutputPlannedIr<B>) -> Self {
        let planned_ir =
            OutputPlannedIr::new(planned_ir.tree().clone(), planned_ir.payloads().clone());
        Self {
            planned_ir: RefCell::new(planned_ir),
        }
    }
}

impl<B: SnarkBackend> Default for GadgetPlanningPass<B> {
    fn default() -> Self {
        todo!("Prover GadgetPlanningPass requires an initialized planned IR")
    }
}

impl<B: SnarkBackend> LocalPass<B, HintDFPayload, HintDFPayload> for GadgetPlanningPass<B> {
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PreOrder
    }

    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: Option<&HintDFPayload>,
    ) -> Option<HintDFPayload> {
        let mut ir = self.planned_ir.borrow_mut();
        if ir.payloads().get(&id).is_none() {
            ir.set_payload_for_node(id, payload.cloned());
        }

        ProverNodeOps::initialize_gadget_plans(node, id, &mut ir)
            .expect("prover gadget planning should succeed");

        let updated = ir.payloads().get(&id).cloned().flatten();
        if updated.is_some() {
            return updated;
        }

        match node {
            Node::Gadget(gadget_node) => {
                Some(PayloadStructure::GadgetPayload(gadget_node.prover_hints()))
            }
            _ => payload.cloned(),
        }
    }
}
