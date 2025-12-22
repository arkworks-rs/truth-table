use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::EmptyPayload,
    },
    verifier::{
        irs::GadgetReadyIr,
        payloads::GadgetReadyPayload,
    },
};
use ark_piop::{SnarkBackend, verifier::ArgVerifier};
use std::cell::RefCell;

/// A verify pass that runs the verifier gadget in each plan node.
///
/// This pass iterates the verifier plan nodes and runs the associated verifier gadget.
pub struct VerifyPass<B: SnarkBackend> {
    arg_verifier: RefCell<ArgVerifier<B>>,
    gadget_ready_ir: RefCell<GadgetReadyIr<B>>,
}

impl<B: SnarkBackend> VerifyPass<B> {
    pub fn new(arg_verifier: ArgVerifier<B>, gadget_ready_ir: GadgetReadyIr<B>) -> Self {
        Self {
            arg_verifier: RefCell::new(arg_verifier),
            gadget_ready_ir: RefCell::new(gadget_ready_ir),
        }
    }
}

impl<B> LocalPass<B, GadgetReadyPayload<B>, EmptyPayload> for VerifyPass<B>
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
                let mut arg_verifier = self.arg_verifier.borrow_mut();
                let mut gadget_ready_ir = self.gadget_ready_ir.borrow_mut();
                gadget_node
                    .verify(&mut arg_verifier, &mut gadget_ready_ir, _id)
                    .expect("gadget verification should succeed");
                Some(EmptyPayload)
            }
            Node::Plan(_) => None,
        }
    }
}
