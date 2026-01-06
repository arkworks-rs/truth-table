use std::cell::RefCell;

use crate::irs::{
    ir::LocalPass,
    nodes::{IsNode, Node, NodeId},
    payloads::{HintDFPayload, PayloadStructure},
    shared_ir::OutputPlannedIr,
};
use ark_piop::SnarkBackend;

/// A planning pass that initializes the IR with hint DataFrames.
///
/// This pass converts an IR with empty payloads into an IR with Hint DataFrames.
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
        todo!("GadgetPlanningPass requires an initialized planned IR")
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

        node.initialize_gadget_plans(id, &mut ir)
            .expect("gadget planning should succeed");

        let updated = ir.payloads().get(&id).cloned().flatten();
        if updated.is_some() {
            return updated;
        }

        match node {
            Node::Gadget(gadget_node) => Some(PayloadStructure::GadgetPayload(gadget_node.hints())),
            _ => payload.cloned(),
        }
    }
}
