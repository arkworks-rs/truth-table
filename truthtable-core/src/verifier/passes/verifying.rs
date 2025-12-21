use std::{any::Any, cell::RefCell};

use ark_piop::{SnarkBackend, verifier::ArgVerifier};

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{IsGadgetNode, Node, NodeId},
        payloads::EmptyPayload,
    },
    verifier::{
        irs::GadgetReadyIr,
        payloads::GadgetReadyPayload,
    },
};

/// A verifying pass that runs the verifier gadget for each gadget node.
pub struct VerifyingPass<B: SnarkBackend> {
    arg_verifier: RefCell<ArgVerifier<B>>,
    gadget_ready_ir: RefCell<GadgetReadyIr<B>>,
}

impl<B: SnarkBackend> VerifyingPass<B> {
    pub fn new(arg_verifier: ArgVerifier<B>, gadget_ready_ir: GadgetReadyIr<B>) -> Self {
        Self {
            arg_verifier: RefCell::new(arg_verifier),
            gadget_ready_ir: RefCell::new(gadget_ready_ir),
        }
    }
}

impl<B> LocalPass<B, GadgetReadyPayload<B>, EmptyPayload> for VerifyingPass<B>
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
                let node_any = gadget_node.as_ref() as &dyn Any;

                let mut arg_verifier = self.arg_verifier.borrow_mut();
                let mut gadget_ready_ir = self.gadget_ready_ir.borrow_mut();

                if let Some(node) = node_any.downcast_ref::<
                    crate::irs::nodes::gadget::exprs::bin_eq::ProverNode<B>,
                >() {
                    node.verify(&mut arg_verifier, &mut gadget_ready_ir, _id)
                        .expect("gadget verification should succeed");
                    return Some(EmptyPayload);
                }
                if let Some(node) = node_any.downcast_ref::<
                    crate::irs::nodes::gadget::lps::filter::ProverNode<B>,
                >() {
                    node.verify(&mut arg_verifier, &mut gadget_ready_ir, _id)
                        .expect("gadget verification should succeed");
                    return Some(EmptyPayload);
                }
                if let Some(node) = node_any.downcast_ref::<
                    crate::irs::nodes::gadget::utils::eq::ProverNode<B>,
                >() {
                    node.verify(&mut arg_verifier, &mut gadget_ready_ir, _id)
                        .expect("gadget verification should succeed");
                    return Some(EmptyPayload);
                }
                if let Some(node) = node_any.downcast_ref::<
                    crate::irs::nodes::gadget::utils::neq::ProverNode<B>,
                >() {
                    node.verify(&mut arg_verifier, &mut gadget_ready_ir, _id)
                        .expect("gadget verification should succeed");
                    return Some(EmptyPayload);
                }

                None
            }
            Node::Plan(_) => None,
        }
    }
}
