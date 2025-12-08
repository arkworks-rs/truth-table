use std::{marker::PhantomData, sync::Arc};

use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, IsPlanNode, Node,
    gadget::{GadgetAncestry, utils::eq},
};

pub struct ProverNode<B: SnarkBackend> {
    col_eq: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Filter".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.col_eq.clone()]
    }
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for ProverNode<B> {
    fn prove(&self, _prover: &mut ark_piop::prover::ArgProver<B>) -> ark_piop::errors::SnarkResult<()> {
        // TODO: implement gadget proof
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn ancestry(&self) -> GadgetAncestry {
        todo!()
    }

    fn new() -> Self
    where
        Self: Sized,
    {
        let col_eq_gadget = Arc::new(Node::<B>::Gadget(Arc::new(eq::ProverNode::new())));
        Self {
            col_eq: col_eq_gadget,
        }
    }
}
