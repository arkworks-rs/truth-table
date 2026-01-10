use std::sync::Arc;

use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::gadget::exprs::aggregate_function::{OUTPUT_LABEL, input_label};
use crate::irs::nodes::gadget::utils::geq;
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub struct GadgetNode<B: SnarkBackend> {
    geq: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Max Aggregate Function".to_string()
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
        vec![self.geq.clone()]
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
            panic!("Expected gadget payload for Max Aggregate Function gadget");
        };

        let output = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Max Aggregate Function missing output payload"));
        let input_0_label = input_label(0);
        let input_0 = payload
            .get(&input_0_label)
            .cloned()
            .unwrap_or_else(|| panic!("Max Aggregate Function missing payload {}", input_0_label));

        debug_assert_eq!(
            output.data_tracked_polys_indices().len(),
            1,
            "Max Aggregate Function output must have exactly one data column"
        );
        debug_assert_eq!(
            input_0.data_tracked_polys_indices().len(),
            1,
            "Max Aggregate Function input_0 must have exactly one data column"
        );

        let output_data_ind = output.data_tracked_polys_indices()[0];
        let output_col = output.tracked_col_by_ind(output_data_ind);
        let output_field = output_col
            .field_ref()
            .expect("Max Aggregate Function output column should have field metadata");
        let output_poly = output_col.data_tracked_poly();
        let input_activator = input_0.activator_tracked_poly();
        let left_table = arithmetic::table::TrackedTable::single_column_with_activator(
            output_field,
            output_poly,
            input_activator,
        );

        let mut geq_payload = match virtualized_ir.payload_for_node(&self.geq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        geq_payload.insert(geq::LEFT_LABEL.to_string(), left_table);
        geq_payload.insert(geq::RIGHT_LABEL.to_string(), input_0);
        virtualized_ir.set_payload_for_node(
            self.geq.id(),
            Some(PayloadStructure::GadgetPayload(geq_payload)),
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
            panic!("Expected gadget payload for Max Aggregate Function gadget");
        };

        let output = payload
            .get(OUTPUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Max Aggregate Function missing output payload"));
        let input_0_label = input_label(0);
        let input_0 = payload
            .get(&input_0_label)
            .cloned()
            .unwrap_or_else(|| panic!("Max Aggregate Function missing payload {}", input_0_label));

        debug_assert_eq!(
            output.data_tracked_oracles_indices().len(),
            1,
            "Max Aggregate Function output must have exactly one data column"
        );
        debug_assert_eq!(
            input_0.data_tracked_oracles_indices().len(),
            1,
            "Max Aggregate Function input_0 must have exactly one data column"
        );

        let output_data_ind = output.data_tracked_oracles_indices()[0];
        let output_col = output.tracked_col_oracle_by_ind(output_data_ind);
        let output_field = output_col
            .field_ref()
            .expect("Max Aggregate Function output column should have field metadata");
        let output_oracle = output_col.data_tracked_oracle();
        let input_activator = input_0.activator_tracked_poly();
        let left_table = arithmetic::table_oracle::TrackedTableOracle::single_column_with_activator(
            output_field,
            output_oracle,
            input_activator,
        );

        let mut geq_payload = match virtualized_ir.payload_for_node(&self.geq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        geq_payload.insert(geq::LEFT_LABEL.to_string(), left_table);
        geq_payload.insert(geq::RIGHT_LABEL.to_string(), input_0);
        virtualized_ir.set_payload_for_node(
            self.geq.id(),
            Some(PayloadStructure::GadgetPayload(geq_payload)),
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
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
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
        let geq = Arc::new(Node::<B>::Gadget(Arc::new(geq::GadgetNode::new())));
        Self { geq }
    }
}
