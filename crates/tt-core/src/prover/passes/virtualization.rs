use std::cell::RefCell;

use arithmetic::table::TrackedTable;
use ark_piop::SnarkBackend;

use crate::irs::ir::PassOrder;
use crate::irs::nodes::ProverNodeOps;
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

/// Lets each node add its virtual witnesses to a shared IR.
pub struct VirtualizationPass<B: SnarkBackend> {
    virtualized_ir: RefCell<VirtualizedIr<B>>,
}

impl<B: SnarkBackend> VirtualizationPass<B> {
    pub fn new(tracked_ir: &TrackedIr<B>) -> Self {
        // Tracking skips a purely virtual node; give it an empty tracked
        // table for this pass to fill.
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
        let updated = {
            let mut ir = self.virtualized_ir.borrow_mut();
            node.add_virtual_witness(id, &mut ir)
                .expect("virtual witness insertion should succeed");
            ir.payloads().get(&id).cloned().flatten()
        };

        // Always emit a payload, an empty tracked table at worst.
        updated
            .or_else(|| payload.cloned())
            .or_else(|| Some(PayloadStructure::PlanPayload(TrackedTable::default())))
    }

    fn fallback_payload(&self, _node: &Node<B>, _id: NodeId) -> Option<TrackedPayload<B>> {
        Some(PayloadStructure::PlanPayload(TrackedTable::default()))
    }

    fn name(&self) -> &'static str {
        "Prover Virtualization"
    }
}
