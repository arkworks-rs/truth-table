use std::sync::Arc;

use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::gadget::exprs::aggregate_function::{
    INPUT_RLC_LABEL, OUTPUT_LABEL, OUTPUT_RLC_LABEL, input_label,
};
use crate::irs::nodes::gadget::utils::keyed_sumcheck;
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub struct GadgetNode<B: SnarkBackend> {
    keyed_sumcheck: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Sum Aggregate Function".to_string()
    }

    fn display(&self) -> String {
        let name = self.name();
        crate::irs::nodes::display_with_inputs(&name, &self.children())
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
        vec![self.keyed_sumcheck.clone()]
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("Expected gadget payload for Sum Aggregate Function gadget");
        };

        let input_rlc = payload
            .get(INPUT_RLC_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Sum Aggregate Function missing input rlc payload"));
        let output_rlc = payload
            .get(OUTPUT_RLC_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Sum Aggregate Function missing output rlc payload"));
        let output_table = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Sum Aggregate Function missing output payload"));
        let input_0_label = input_label(0);
        let input_0 = payload
            .get(&input_0_label)
            .cloned()
            .unwrap_or_else(|| panic!("Sum Aggregate Function missing payload {}", input_0_label));

        let mut keyed_sumcheck_payload =
            match virtualized_ir.payload_for_node(&self.keyed_sumcheck.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

        keyed_sumcheck_payload.insert(keyed_sumcheck::FXS_LABEL.to_string(), input_rlc);
        keyed_sumcheck_payload.insert(keyed_sumcheck::MFXS_LABEL.to_string(), input_0);
        keyed_sumcheck_payload.insert(keyed_sumcheck::GXS_LABEL.to_string(), output_rlc);
        keyed_sumcheck_payload.insert(keyed_sumcheck::MGXS_LABEL.to_string(), output_table);

        virtualized_ir.set_payload_for_node(
            self.keyed_sumcheck.id(),
            Some(PayloadStructure::GadgetPayload(keyed_sumcheck_payload)),
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("Expected gadget payload for Sum Aggregate Function gadget");
        };

        let input_rlc = payload
            .get(INPUT_RLC_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Sum Aggregate Function missing input rlc payload"));
        let output_rlc = payload
            .get(OUTPUT_RLC_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Sum Aggregate Function missing output rlc payload"));
        let output_table = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Sum Aggregate Function missing output payload"));
        let input_0_label = input_label(0);
        let input_0 = payload
            .get(&input_0_label)
            .cloned()
            .unwrap_or_else(|| panic!("Sum Aggregate Function missing payload {}", input_0_label));

        let mut keyed_sumcheck_payload =
            match virtualized_ir.payload_for_node(&self.keyed_sumcheck.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

        keyed_sumcheck_payload.insert(keyed_sumcheck::FXS_LABEL.to_string(), input_rlc);
        keyed_sumcheck_payload.insert(keyed_sumcheck::MFXS_LABEL.to_string(), input_0);
        keyed_sumcheck_payload.insert(keyed_sumcheck::GXS_LABEL.to_string(), output_rlc);
        keyed_sumcheck_payload.insert(keyed_sumcheck::MGXS_LABEL.to_string(), output_table);

        virtualized_ir.set_payload_for_node(
            self.keyed_sumcheck.id(),
            Some(PayloadStructure::GadgetPayload(keyed_sumcheck_payload)),
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

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        let keyed_sumcheck_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            keyed_sumcheck::GadgetNode::new(),
        )));
        Self {
            keyed_sumcheck: keyed_sumcheck_gadget,
        }
    }
}
