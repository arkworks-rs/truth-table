use std::sync::Arc;

use arithmetic::{is_system_column, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, gadget::utils::sign},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const LEFT_LABEL: &str = "left";
pub const RIGHT_LABEL: &str = "right";

pub struct GadgetNode<B: SnarkBackend> {
    sign: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Leq".to_string()
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

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.sign.clone()]
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
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(left_input), Some(right_input)) = (
            payload.get(LEFT_LABEL).cloned(),
            payload.get(RIGHT_LABEL).cloned(),
        ) else {
            panic!("Expected left and right inputs for leq gadget");
        };

        debug_assert_eq!(
            left_input.data_tracked_polys_indices().len(),
            1,
            "Leq gadget supports one tracked polynomial per input."
        );
        debug_assert_eq!(
            right_input.data_tracked_polys_indices().len(),
            1,
            "Leq gadget supports one tracked polynomial per input."
        );
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Leq gadget inputs must share the same activator polynomial"
        );

        let left_data_ind = left_input.data_tracked_polys_indices()[0];
        let right_data_ind = right_input.data_tracked_polys_indices()[0];
        let left_col = left_input.tracked_col_by_ind(left_data_ind);
        let right_col = right_input.tracked_col_by_ind(right_data_ind);
        let diff_poly = &left_col.data_tracked_poly() - &right_col.data_tracked_poly();

        let data_field = left_input
            .tracked_polys()
            .keys()
            .find(|field| !is_system_column(field.name()))
            .cloned()
            .expect("Leq left input should include a data column");
        let diff_table = TrackedTable::single_column_with_activator(
            data_field,
            diff_poly,
            left_col.activator_tracked_poly(),
        );

        let mut sign_payload = match virtualized_ir.payload_for_node(&self.sign.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        sign_payload.insert(sign::INPUT_LABEL.to_string(), diff_table);
        virtualized_ir.set_payload_for_node(
            self.sign.id(),
            Some(PayloadStructure::GadgetPayload(sign_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(left_input), Some(right_input)) = (
            payload.get(LEFT_LABEL).cloned(),
            payload.get(RIGHT_LABEL).cloned(),
        ) else {
            panic!("Expected left and right inputs for leq gadget");
        };

        debug_assert_eq!(
            left_input.data_tracked_oracles_indices().len(),
            1,
            "Leq gadget supports one tracked oracle per input."
        );
        debug_assert_eq!(
            right_input.data_tracked_oracles_indices().len(),
            1,
            "Leq gadget supports one tracked oracle per input."
        );
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Leq gadget inputs must share the same activator oracle"
        );

        let left_data_ind = left_input.data_tracked_oracles_indices()[0];
        let right_data_ind = right_input.data_tracked_oracles_indices()[0];
        let left_col = left_input.tracked_col_oracle_by_ind(left_data_ind);
        let right_col = right_input.tracked_col_oracle_by_ind(right_data_ind);
        let diff_oracle = &left_col.data_tracked_oracle() - &right_col.data_tracked_oracle();

        let data_field = left_input
            .tracked_oracles()
            .keys()
            .find(|field| !is_system_column(field.name()))
            .cloned()
            .expect("Leq left input should include a data column");
        let diff_table = TrackedTableOracle::single_column_with_activator(
            data_field,
            diff_oracle,
            left_col.activator_tracked_oracle(),
        );

        let mut sign_payload = match virtualized_ir.payload_for_node(&self.sign.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        sign_payload.insert(sign::INPUT_LABEL.to_string(), diff_table);
        virtualized_ir.set_payload_for_node(
            self.sign.id(),
            Some(PayloadStructure::GadgetPayload(sign_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        <Self as ProverNodeOps<B>>::initialize_gadget_plans(self, id, planned_ir)
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
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

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
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
        let sign_gadget = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::SignConfig::Uniform(sign::Sign::NonPositive),
        ))));
        Self { sign: sign_gadget }
    }
}
