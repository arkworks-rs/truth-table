use std::cell::RefCell;

use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::SnarkBackend;

use crate::irs::ir::{LocalPass, PassOrder};
use crate::irs::nodes::{Node, NodeId, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::verifier::irs::VirtualizedIr;
use crate::verifier::payloads::{GadgetReadyPayload, VirtualizedPayload};

/// A pass that lets parent plan nodes initialize their gadget payloads in pre-order.
pub struct GadgetInitializationPass<B: SnarkBackend> {
    virtualized_ir: RefCell<VirtualizedIr<B>>,
    verifier: ark_piop::verifier::ArgVerifier<B>,
}

impl<B: SnarkBackend> GadgetInitializationPass<B> {
    pub fn new(
        virtualized_ir: VirtualizedIr<B>,
        verifier: ark_piop::verifier::ArgVerifier<B>,
    ) -> Self {
        Self {
            virtualized_ir: RefCell::new(virtualized_ir),
            verifier,
        }
    }
}

impl<B> LocalPass<B, VirtualizedPayload<B>, GadgetReadyPayload<B>> for GadgetInitializationPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> PassOrder {
        PassOrder::PreOrder
    }

    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: Option<&VirtualizedPayload<B>>,
    ) -> Option<GadgetReadyPayload<B>> {
        let mut ir = self.virtualized_ir.borrow_mut();
        // Seed payload if missing.
        if ir.payloads().get(&id).is_none() {
            ir.set_payload_for_node(id, payload.cloned());
        }

        let mut verifier = self.verifier.clone();
        node.initialize_gadgets(id, &mut verifier, &mut ir)
            .expect("gadget initialization should succeed");

        ir.payloads()
            .get(&id)
            .cloned()
            .flatten()
            .or_else(|| payload.cloned())
    }

    fn fallback_payload(&self, _node: &Node<B>, _id: NodeId) -> Option<GadgetReadyPayload<B>> {
        Some(PayloadStructure::PlanPayload(TrackedTableOracle::default()))
    }

    fn name(&self) -> &'static str {
        "Gadget Initialization"
    }
}
