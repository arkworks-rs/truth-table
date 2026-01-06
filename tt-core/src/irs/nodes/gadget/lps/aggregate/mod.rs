use std::sync::Arc;

use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::gadget::utils::supp;
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";

pub struct GadgetNode<B: SnarkBackend> {
    supp_gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Aggregate".to_string()
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
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let aggregate_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };

        let input_hint = match aggregate_payload.get(INPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let output_hint = match aggregate_payload.get(OUTPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        let mut supp_payload = match planned_ir.payload_for_node(&self.supp_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_hint);
        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_hint);

        planned_ir.set_payload_for_node(
            self.supp_gadget.id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
        );
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.supp_gadget.clone()]
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
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => panic!("Expected gadget payload for aggregate node"),
        };

        let (input_table, output_table) = match (
            gadget_payload.get(INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(input), Some(output)) => (input.clone(), output.clone()),
            _ => panic!("Expected aggregate input and output tables"),
        };

        let mut supp_payload = match virtualized_ir.payload_for_node(&self.supp_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_table);
        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_table);

        virtualized_ir.set_payload_for_node(
            self.supp_gadget.id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
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
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => panic!("Expected gadget payload for aggregate node"),
        };

        let (input_table, output_table) = match (
            gadget_payload.get(INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(input), Some(output)) => (input.clone(), output.clone()),
            _ => panic!("Expected aggregate input and output tables"),
        };

        let mut supp_payload = match virtualized_ir.payload_for_node(&self.supp_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_table);
        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_table);

        virtualized_ir.set_payload_for_node(
            self.supp_gadget.id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
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

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let supp_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::supp::GadgetNode::new(),
        )));
        Self { supp_gadget }
    }
}
