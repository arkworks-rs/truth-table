use crate::{
    irs::{
        ir::LocalPass,
        nodes::{IsNode, Node, NodeId},
        payloads::EmptyPayload,
    },
    verifier::{irs::GadgetReadyIr, payloads::GadgetReadyPayload},
};
use ark_piop::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    verifier::{ArgVerifier, errors::VerifierError},
};
use std::cell::RefCell;

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
        id: NodeId,
        _payload: Option<&GadgetReadyPayload<B>>,
    ) -> Option<EmptyPayload> {
        if self.error.borrow().is_some() {
            return None;
        }
        match node {
            Node::Gadget(gadget_node) => {
                let should_log_parent = tracing::level_enabled!(tracing::Level::DEBUG)
                    || tracing::level_enabled!(tracing::Level::INFO);
                let parent_name = if should_log_parent {
                    let gadget_ready_ir = self.gadget_ready_ir.borrow();
                    parent_name_for(gadget_ready_ir.tree(), id)
                        .unwrap_or_else(|| "<none>".to_string())
                } else {
                    String::new()
                };
                if tracing::level_enabled!(tracing::Level::DEBUG) {
                    tracing::debug!(
                        gadget = %gadget_node.name(),
                        parent = %parent_name,
                        "starting to verify gadget"
                    );
                }
                let result = {
                    let mut arg_verifier = self.arg_verifier.borrow_mut();
                    let mut gadget_ready_ir = self.gadget_ready_ir.borrow_mut();
                    gadget_node.verify(&mut arg_verifier, &mut gadget_ready_ir, id)
                };
                if let Err(err) = result {
                    *self.error.borrow_mut() = Some(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(format!(
                            "verify pass failed in gadget {} under parent {}: {:?}",
                            gadget_node.name(),
                            parent_name,
                            err
                        )),
                    ));
                    None
                } else {
                    if tracing::level_enabled!(tracing::Level::INFO) {
                        tracing::info!(
                            gadget = %gadget_node.name(),
                            parent = %parent_name,
                            "gadget was verified"
                        );
                    }
                    Some(EmptyPayload)
                }
            }
            Node::Plan(_) => None,
        }
    }

    fn name(&self) -> &'static str {
        "Verifier Verification"
    }
}
