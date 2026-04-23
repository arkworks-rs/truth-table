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
    piop::DeepClone,
    prover::ArgProver,
};
use indexmap::IndexMap;
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

fn deep_clone_payload<B: SnarkBackend>(
    payload: &GadgetReadyPayload<B>,
    prover: &ArgProver<B>,
) -> GadgetReadyPayload<B> {
    match payload {
        GadgetReadyPayload::PlanPayload(table) => {
            GadgetReadyPayload::PlanPayload(table.deep_clone(prover.clone()))
        }
        GadgetReadyPayload::GadgetPayload(map) => GadgetReadyPayload::GadgetPayload(
            map.iter()
                .map(|(key, table)| (key.clone(), table.deep_clone(prover.clone())))
                .collect::<IndexMap<_, _>>(),
        ),
    }
}

fn deep_clone_gadget_ready_ir<B: SnarkBackend>(
    ir: &GadgetReadyIr<B>,
    prover: &ArgProver<B>,
) -> GadgetReadyIr<B> {
    // Deep-clone payload tables so honest checks don't mutate the main tracker.
    let payloads = ir
        .payloads()
        .iter()
        .map(|(id, payload)| {
            (
                *id,
                payload
                    .as_ref()
                    .map(|inner| deep_clone_payload(inner, prover)),
            )
        })
        .collect::<IndexMap<_, _>>();
    GadgetReadyIr::new(ir.tree().clone(), payloads)
}

/// A proving pass that runs honest prover checks for each gadget.
///
/// This pass mirrors `ProvingPass`, but dispatches to `honest_prover_check`
/// instead of `prove`.
pub struct HonestProverPass<B: SnarkBackend> {
    arg_prover: RefCell<ArgProver<B>>,
    gadget_ready_ir: RefCell<GadgetReadyIr<B>>,
    error: RefCell<Option<SnarkError>>,
}

impl<B: SnarkBackend> HonestProverPass<B> {
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

impl<B> LocalPass<B, GadgetReadyPayload<B>, EmptyPayload> for HonestProverPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PreOrder
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
                    "starting honest prover check for gadget"
                );
                let result = {
                    let gadget_ready_ir = self.gadget_ready_ir.borrow();
                    let arg_prover = self.arg_prover.borrow();
                    let mut honest_prover = arg_prover.deep_copy();
                    let mut gadget_ready_ir_clone =
                        deep_clone_gadget_ready_ir(&gadget_ready_ir, &honest_prover);
                    gadget_node.honest_prover_check(
                        &mut honest_prover,
                        &mut gadget_ready_ir_clone,
                        id,
                    )
                };
                if let Err(err) = result {
                    tracing::error!(
                        gadget = %gadget_node.name(),
                        parent = %parent_name,
                        error = %err,
                        "honest prover check failed"
                    );
                    *self.error.borrow_mut() = Some(err);
                    None
                } else {
                    tracing::info!(
                        gadget = %gadget_node.name(),
                        parent = %parent_name,
                        "honest prover check completed"
                    );
                    Some(EmptyPayload)
                }
            }
            Node::Plan(_) => None,
        }
    }

    fn name(&self) -> &'static str {
        "Honest Prover Check"
    }
}
