use std::marker::PhantomData;

use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::{IsGadgetNode, IsNode, IsPlanNode, Node};

pub struct ProverNode<B: SnarkBackend>(PhantomData<B>);

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Filter Gadget".to_string()
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
}

impl<B: SnarkBackend> IsGadgetNode<B> for ProverNode<B> {
    fn prove() -> ark_piop::errors::SnarkResult<()>
    where
        Self: Sized,
    {
        todo!()
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn ancestry(&self) -> super::GadgetAncestry {
        todo!()
    }

    fn new() -> Self
    where
        Self: Sized,
    {
        Self(PhantomData)
    }
}
