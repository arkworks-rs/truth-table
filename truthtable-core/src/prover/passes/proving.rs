use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::EmptyPayload,
    },
    prover::{
        irs::GadgetReadyIr,
        payloads::GadgetReadyPayload,
    },
};
use ark_piop::{SnarkBackend, prover::ArgProver};
use std::cell::RefCell;

/// A proving pass that run the prover gadget in each plan node
///
/// This pass iterates the prover plan nodes and runs the associated prover gadget
pub struct ProvingPass<B: SnarkBackend> {
    arg_prover: RefCell<ArgProver<B>>,
    gadget_ready_ir: RefCell<GadgetReadyIr<B>>,
}

impl<B: SnarkBackend> ProvingPass<B> {
    pub fn new(arg_prover: ArgProver<B>, gadget_ready_ir: GadgetReadyIr<B>) -> Self {
        Self {
            arg_prover: RefCell::new(arg_prover),
            gadget_ready_ir: RefCell::new(gadget_ready_ir),
        }
    }
}

impl<B> LocalPass<B, GadgetReadyPayload<B>, EmptyPayload> for ProvingPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        _payload: Option<&GadgetReadyPayload<B>>,
    ) -> Option<EmptyPayload> {
        match node {
            Node::Gadget(gadget_node) => {
                let mut arg_prover = self.arg_prover.borrow_mut();
                let mut gadget_ready_ir = self.gadget_ready_ir.borrow_mut();
                gadget_node
                    .prove(&mut arg_prover, &mut gadget_ready_ir, _id)
                    .expect("gadget proving should succeed");
                Some(EmptyPayload)
            }
            Node::Plan(_) => None,
        }
    }
}
