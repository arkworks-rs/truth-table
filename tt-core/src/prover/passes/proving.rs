use crate::{
    irs::{
        ir::LocalPass,
        nodes::{IsNode, Node, NodeId},
        payloads::EmptyPayload,
    },
    prover::{irs::GadgetReadyIr, payloads::GadgetReadyPayload},
};
use ark_piop::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    prover::ArgProver,
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

/// A proving pass that run the prover gadget in each plan node
///
/// This pass iterates the prover plan nodes and runs the associated prover gadget
pub struct ProvingPass<B: SnarkBackend> {
    arg_prover: RefCell<ArgProver<B>>,
    gadget_ready_ir: RefCell<GadgetReadyIr<B>>,
    error: RefCell<Option<SnarkError>>,
}

impl<B: SnarkBackend> ProvingPass<B> {
    pub fn new(arg_prover: ArgProver<B>, gadget_ready_ir: GadgetReadyIr<B>) -> Self {
        Self {
            arg_prover: RefCell::new(arg_prover),
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

impl<B> LocalPass<B, GadgetReadyPayload<B>, EmptyPayload> for ProvingPass<B>
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
                let parent_name = {
                    let gadget_ready_ir = self.gadget_ready_ir.borrow();
                    parent_name_for(gadget_ready_ir.tree(), id)
                        .unwrap_or_else(|| "<none>".to_string())
                };
                tracing::debug!(
                    gadget = %gadget_node.name(),

                    parent = %parent_name,
                    "starting to prove gadget"
                );
                let result = {
                    let mut arg_prover = self.arg_prover.borrow_mut();
                    let mut gadget_ready_ir = self.gadget_ready_ir.borrow_mut();
                    gadget_node.prove(&mut arg_prover, &mut gadget_ready_ir, id)
                };
                if let Err(err) = result {
                    *self.error.borrow_mut() = Some(err);
                    None
                } else {
                    tracing::info!(
                        gadget = %gadget_node.name(),

                        parent = %parent_name,
                        "gadget was proved"
                    );
                    Some(EmptyPayload)
                }
            }
            Node::Plan(_) => None,
        }
    }
    
    fn name(&self) -> &'static str {
        "Prover Proving"
    }
}
