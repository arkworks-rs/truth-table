use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
        payloads::EmptyPayload,
    },
    verifier::{irs::GadgetReadyIr, payloads::GadgetReadyPayload},
};
use ark_piop::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    verifier::ArgVerifier,
};
use std::cell::RefCell;

/// A verify pass that runs the verifier gadget in each plan node.
///
/// This pass iterates the verifier plan nodes and runs the associated verifier gadget.
pub struct VerifyPass<B: SnarkBackend> {
    arg_verifier: RefCell<ArgVerifier<B>>,
    gadget_ready_ir: RefCell<GadgetReadyIr<B>>,
    error: RefCell<Option<SnarkError>>,
}

impl<B: SnarkBackend> VerifyPass<B> {
    pub fn new(arg_verifier: ArgVerifier<B>, gadget_ready_ir: GadgetReadyIr<B>) -> Self {
        Self {
            arg_verifier: RefCell::new(arg_verifier),
            gadget_ready_ir: RefCell::new(gadget_ready_ir),
            error: RefCell::new(None),
        }
    }

    pub fn take_result(&self) -> SnarkResult<()> {
        match self.error.borrow_mut().take() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

impl<B> LocalPass<B, GadgetReadyPayload<B>, EmptyPayload> for VerifyPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }
    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        _payload: Option<&GadgetReadyPayload<B>>,
    ) -> Option<EmptyPayload> {
        if self.error.borrow().is_some() {
            return None;
        }
        match node {
            Node::Gadget(gadget_node) => {
                let result = {
                    let mut arg_verifier = self.arg_verifier.borrow_mut();
                    let mut gadget_ready_ir = self.gadget_ready_ir.borrow_mut();
                    gadget_node.verify(&mut arg_verifier, &mut gadget_ready_ir, _id)
                };
                if let Err(err) = result {
                    *self.error.borrow_mut() = Some(err);
                    None
                } else {
                    Some(EmptyPayload)
                }
            }
            Node::Plan(_) => None,
        }
    }
}
