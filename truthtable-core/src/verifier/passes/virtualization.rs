use std::cell::RefCell;

use ark_piop::SnarkBackend;

use crate::irs::payloads::PayloadStructure;
use crate::irs::{
    ir::LocalPass,
    ir::PassOrder,
    nodes::{Node, NodeId},
};
use crate::verifier::irs::{TrackedIr, VirtualizedIr};
use crate::verifier::payloads::{TrackedPayload, VirtualizedPayload};
use arithmetic::table_oracle::TrackedTableOracle;

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
                (*id, payload.clone())
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
        // Verifier side does not inject virtual witnesses; simply forward tracked payloads.
        payload.cloned()
    }

    fn fallback_payload(&self, _node: &Node<B>, _id: NodeId) -> Option<TrackedPayload<B>> {
        None
    }
}
