use std::cell::RefCell;
use std::collections::HashSet;

use crate::irs::{
    ir::LocalPass,
    nodes::{Node, NodeId, VerifierNodeOps, gadget::lps::join},
    payloads::{HintDFDFPayload, HintDFPayload, PayloadStructure},
    shared_ir::OutputPlannedIr,
};
use ark_piop::SnarkBackend;

/// Verifier-side gadget planning pass.
///
/// This pass executes pre-order and lets each node update verifier planning hints.
pub struct GadgetPlanningPass<B: SnarkBackend> {
    planned_ir: RefCell<OutputPlannedIr<B>>,
    visited_nodes: RefCell<Option<HashSet<NodeId>>>,
}

impl<B: SnarkBackend> GadgetPlanningPass<B> {
    pub fn new(planned_ir: &OutputPlannedIr<B>) -> Self {
        let planned_ir = planned_ir.clone();
        Self {
            planned_ir: RefCell::new(planned_ir),
            visited_nodes: RefCell::new(None),
        }
    }
}

impl<B: SnarkBackend> Default for GadgetPlanningPass<B> {
    fn default() -> Self {
        todo!("Verifier GadgetPlanningPass requires an initialized planned IR")
    }
}

impl<B: SnarkBackend> LocalPass<B, HintDFDFPayload, HintDFDFPayload> for GadgetPlanningPass<B> {
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PreOrder
    }

    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: Option<&HintDFDFPayload>,
    ) -> Option<HintDFDFPayload> {
        if self
            .visited_nodes
            .borrow()
            .as_ref()
            .is_some_and(|visited| visited.contains(&id))
        {
            return self
                .planned_ir
                .borrow()
                .payloads()
                .get(&id)
                .cloned()
                .flatten()
                .or_else(|| match node {
                    Node::Gadget(gadget_node) => Some(PayloadStructure::GadgetPayload(
                        gadget_node.verifier_hints(),
                    )),
                    _ => payload.cloned(),
                });
        }

        let mut ir = self.planned_ir.borrow_mut();
        if ir.payloads().get(&id).is_none() {
            ir.set_payload_for_node(id, payload.cloned());
        }

        VerifierNodeOps::initialize_gadget_plans(node, id, &mut ir)
            .expect("verifier gadget planning should succeed");

        if let Some(visited) = self.visited_nodes.borrow_mut().as_mut() {
            visited.insert(id);
        }

        if let Some(updated) = ir.payloads().get(&id).cloned().flatten() {
            Some(updated)
        } else {
            match node {
                Node::Gadget(gadget_node) => Some(PayloadStructure::GadgetPayload(
                    gadget_node.verifier_hints(),
                )),
                _ => payload.cloned(),
            }
        }
    }

    fn begin_pass(&self, _ir: &crate::irs::ir::Ir<B, HintDFDFPayload>) {
        join::begin_join_planning_cache_scope();
        *self.visited_nodes.borrow_mut() = Some(HashSet::new());
    }

    fn end_pass(&self) {
        join::end_join_planning_cache_scope();
        *self.visited_nodes.borrow_mut() = None;
    }

    fn name(&self) -> &'static str {
        "Verifier Gadget Planning"
    }
}
