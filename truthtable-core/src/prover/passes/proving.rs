use crate::{
    irs::{ir::LocalPass, nodes::{Node, NodeId}, payloads::EmptyPayload},
    prover::payloads::TrackedPayload,
};
use ark_piop::{SnarkBackend, prover::ArgProver};
use std::cell::RefCell;

/// A proving pass that run the prover gadget in each plan node
///
/// This pass iterates the prover plan nodes and runs the associated prover gadget
pub struct ProvingPass<B: SnarkBackend> {
    arg_prover: RefCell<ArgProver<B>>,
}

impl<B: SnarkBackend> ProvingPass<B> {
    pub fn new(arg_prover: ArgProver<B>) -> Self {
        Self { arg_prover: RefCell::new(arg_prover) }
    }
}

impl<B> LocalPass<B, TrackedPayload<B>, EmptyPayload> for ProvingPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        _payload: Option<&TrackedPayload<B>>,
    ) -> Option<EmptyPayload> {
        match node {
            Node::Gadget(gadget_node) => {
                gadget_node
                    .prove(&mut self.arg_prover.borrow_mut())
                    .expect("gadget proving should succeed");
                Some(EmptyPayload)
            }
            Node::Plan(_) => None,
        }
    }
}
