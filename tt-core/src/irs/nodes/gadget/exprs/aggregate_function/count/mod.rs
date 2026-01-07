use std::sync::Arc;

use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::gadget::utils::eq;
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;
pub const SUPER_MULTIPLICITIES_LABEL: &str = "__super_multiplicities__";
pub const COUNT_AGGR_EXPR_LABEL: &str = "__count_aggr_expr__";
pub struct GadgetNode<B: SnarkBackend> {
    eq: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Count Aggregate Function".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.eq.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };

        let Some(super_multiplicities) = payload.get(SUPER_MULTIPLICITIES_LABEL).cloned() else {
            return Ok(());
        };
        let Some(count_aggr_expr) = payload.get(COUNT_AGGR_EXPR_LABEL).cloned() else {
            return Ok(());
        };

        let mut eq_payload = match virtualized_ir.payload_for_node(&self.eq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        eq_payload.insert(eq::LEFT_LABEL.to_string(), super_multiplicities);
        eq_payload.insert(eq::RIGHT_LABEL.to_string(), count_aggr_expr);
        virtualized_ir.set_payload_for_node(
            self.eq.id(),
            Some(PayloadStructure::GadgetPayload(eq_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };

        let Some(super_multiplicities) = payload.get(SUPER_MULTIPLICITIES_LABEL).cloned() else {
            return Ok(());
        };
        let Some(count_aggr_expr) = payload.get(COUNT_AGGR_EXPR_LABEL).cloned() else {
            return Ok(());
        };

        let mut eq_payload = match virtualized_ir.payload_for_node(&self.eq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        eq_payload.insert(eq::LEFT_LABEL.to_string(), super_multiplicities);
        eq_payload.insert(eq::RIGHT_LABEL.to_string(), count_aggr_expr);
        virtualized_ir.set_payload_for_node(
            self.eq.id(),
            Some(PayloadStructure::GadgetPayload(eq_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // TODO: implement gadget proof
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let eq_gadget = Arc::new(Node::<B>::Gadget(Arc::new(eq::GadgetNode::new())));
        Self { eq: eq_gadget }
    }
}
