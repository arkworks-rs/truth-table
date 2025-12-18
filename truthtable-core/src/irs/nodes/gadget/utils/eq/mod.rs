use core::panic;
use std::{marker::PhantomData, sync::Arc};

use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::{
    irs::nodes::{IsGadgetNode, IsNode, IsPlanNode, Node, gadget::GadgetAncestry},
    irs::payloads::PayloadStructure,
    prover::irs::GadgetReadyIr,
};

pub const LEFT_LABEL: &str = "left";
pub const RIGHT_LABEL: &str = "right";

pub struct ProverNode<B: SnarkBackend>(PhantomData<B>);

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Eq".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for ProverNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        dbg!("Proving Eq gadget");
        // Identify this gadget's node id inside the gadget-ready IR.
        let self_ptr: *const dyn IsGadgetNode<B> = self;
        let node_id = gadget_ready_ir
            .tree()
            .arena()
            .iter()
            .find_map(|(id, node)| match node.as_ref() {
                Node::Gadget(gadget) if std::ptr::eq(self_ptr, Arc::as_ptr(gadget)) => Some(*id),
                _ => None,
            })
            .expect("gadget node should exist in the IR arena");

        // Fetch the left/right tracked tables prepared for this gadget.
        let Some(PayloadStructure::GadgetPayload(payload)) =
            gadget_ready_ir.payload_for_node(&node_id)
        else {
            panic!("gadget payload should exist for Eq gadget")
        };
        let (Some(left_input), Some(right_input)) = (
            payload.get(LEFT_LABEL).cloned(),
            payload.get(RIGHT_LABEL).cloned(),
        ) else {
            panic!("left/right inputs should exist for Eq gadget")
        };


        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
    fn new() -> Self
    where
        Self: Sized,
    {
        Self(PhantomData)
    }
}
