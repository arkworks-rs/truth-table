use std::cell::RefCell;

use ark_piop::SnarkBackend;

use crate::irs::ir::Ir;
use crate::irs::nodes::VerifierNodeOps;
use crate::irs::payloads::PayloadStructure;
use crate::irs::{
    ir::LocalPass,
    ir::PassOrder,
    nodes::{IsNode, Node, NodeId},
};
use crate::verifier::irs::{TrackedIr, VirtualizedIr};
use crate::verifier::payloads::{TrackedPayload, VirtualizedPayload};
use arithmetic::table_oracle::TrackedTableOracle;

fn parent_name_for<B: SnarkBackend>(
    tree: &crate::irs::tree::Tree<B>,
    id: NodeId,
) -> Option<String> {
    for (_parent_id, node) in tree.arena().iter() {
        if node.children().iter().any(|child| child.id() == id) {
            return Some(node.name());
        }
    }
    None
}

/// A virtualization pass that allows nodes to inject virtual witnesses into the IR
///
/// This pass provides each node with a mutable view of a shared IR, allowing them to
/// insert virtual witnesses as needed.
pub struct VirtualizationPass<B: SnarkBackend> {
    // Mutable view so each node can add virtual witnesses into the shared IR.
    virtualized_ir: RefCell<VirtualizedIr<B>>,
}

impl<B: SnarkBackend> VirtualizationPass<B> {
    pub fn new(tracked_ir: &TrackedIr<B>) -> Self {
        // Seed the virtualized IR with tracked payloads when present; for nodes that were
        // purely virtual (and thus skipped by tracking), give them an empty tracked table so
        // the pass can still run and populate real payloads.
        let seeded_payloads = tracked_ir
            .payloads()
            .iter()
            .map(|(id, payload)| (*id, payload.clone()))
            .collect();

        let virtualized_ir = Ir::new(tracked_ir.tree().clone(), seeded_payloads);
        Self {
            virtualized_ir: RefCell::new(virtualized_ir),
        }
    }
}

impl<B> LocalPass<B, TrackedPayload<B>, VirtualizedPayload<B>> for VirtualizationPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> PassOrder {
        PassOrder::PostOrder
    }

    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: Option<&TrackedPayload<B>>,
    ) -> Option<VirtualizedPayload<B>> {
        // Let each node inject its virtual witness into the shared IR view.
        let updated = {
            let mut ir = self.virtualized_ir.borrow_mut();
            if let Err(err) = node.add_virtual_witness(id, &mut ir) {
                let parent = parent_name_for(ir.tree(), id).unwrap_or_else(|| "<none>".to_string());
                panic!(
                    "virtual witness insertion should succeed for node {} under parent {}: {:?}",
                    node.name(),
                    parent,
                    err
                );
            }
            ir.payloads().get(&id).cloned().flatten()
        };

        // Always emit a payload: prefer the updated value, otherwise default to the incoming
        // tracked payload, and finally fall back to an empty tracked table so columns do not
        // remain empty.
        updated
            .or_else(|| payload.cloned())
            .or_else(|| Some(PayloadStructure::PlanPayload(TrackedTableOracle::default())))
    }

    fn fallback_payload(&self, _node: &Node<B>, _id: NodeId) -> Option<TrackedPayload<B>> {
        Some(PayloadStructure::PlanPayload(TrackedTableOracle::default()))
    }

    fn name(&self) -> &'static str {
        "Verifier Virtualization"
    }
}
