use std::cell::RefCell;

use arithmetic::table::TrackedTable;
use ark_piop::SnarkBackend;

use crate::irs::ir::PassOrder;
use crate::irs::nodes::NodeVirtualWitnessOps;
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::{TrackedIr, VirtualizedIr};
use crate::prover::payloads::VirtualizedPayload;
use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::TrackedPayload,
};

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
            .map(|(id, payload)| {
                let initial = payload
                    .clone()
                    .or_else(|| Some(PayloadStructure::PlanPayload(TrackedTable::default())));
                (*id, initial)
            })
            .collect();

        let virtualized_ir = VirtualizedIr::new(tracked_ir.tree().clone(), seeded_payloads);
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
            NodeVirtualWitnessOps::add_virtual_witness(node, id, &mut ir)
                .expect("virtual witness insertion should succeed");
            ir.payloads().get(&id).cloned().flatten()
        };

        // Always emit a payload: prefer the updated value, otherwise default to the incoming
        // tracked payload, and finally fall back to an empty tracked table so columns do not
        // remain empty.
        updated
            .or_else(|| payload.cloned())
            .or_else(|| Some(PayloadStructure::PlanPayload(TrackedTable::default())))
    }

    fn fallback_payload(&self, _node: &Node<B>, _id: NodeId) -> Option<TrackedPayload<B>> {
        Some(PayloadStructure::PlanPayload(TrackedTable::default()))
    }
}
