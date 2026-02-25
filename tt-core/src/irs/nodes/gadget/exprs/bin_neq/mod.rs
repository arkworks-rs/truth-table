use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, is_system_column, table::TrackedTable};
use ark_ff::One;
use ark_piop::SnarkBackend;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
    gadget::utils::{bool, eq, neq},
};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub const LEFT_INPUT_LABEL: &str = "left_input";
pub const RIGHT_INPUT_LABEL: &str = "right_input";
pub const OUTPUT_LABEL: &str = "output";
pub struct BinNeqNode<B: SnarkBackend> {
    eq: Arc<Node<B>>,
    neq: Arc<Node<B>>,
    bool_check: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for BinNeqNode<B> {
    fn name(&self) -> String {
        "Binary Inequality".to_string()
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
        vec![self.bool_check.clone(), self.eq.clone(), self.neq.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for BinNeqNode<B> {
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
        // Fetch the payload for this gadget node.
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        // Extract the left, right, and output tracked tables from the payload.
        let (left_input, right_input, output) = match (
            gadget_payload.get(LEFT_INPUT_LABEL),
            gadget_payload.get(RIGHT_INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(left), Some(right), Some(output)) => {
                (left.clone(), right.clone(), output.clone())
            }
            _ => panic!("Expected left, right, and output tables for binary inequality gadget"),
        };

        // Ensure that the left and right inputs and output share the same activator polynomial. otherwise a binary operation on those inputs is invalid.
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Left and right inputs must share the same activator polynomial"
        );

        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            output.activator_tracked_poly(),
            "Left input and output must share the same activator polynomial"
        );

        // Now that we are sure that the left and right inputs share the same activator polynomial, we get this activator.
        let shared_activator = left_input.activator_tracked_poly();

        let output_ind = output.data_tracked_polys_indices()[0];
        let output_poly = output.tracked_col_by_ind(output_ind).data_tracked_poly();

        let build_table_with_activator = |table: &TrackedTable<B>, activator: &TrackedPoly<B>| {
            let mut polys = IndexMap::new();
            for (field, poly) in table.tracked_polys_iter() {
                if is_system_column(field.name()) {
                    continue;
                }
                polys.insert(field.clone(), poly.clone());
            }
            polys.insert(ACTIVATOR_FIELD.clone(), activator.clone());

            let metadata = table
                .schema_ref()
                .map(|s| s.metadata().clone())
                .unwrap_or_default();
            let fields = polys.keys().map(|f| f.as_ref().clone()).collect::<Vec<_>>();
            let schema = Some(Schema::new_with_metadata(fields, metadata));

            TrackedTable::new(schema, polys, table.log_size())
        };

        // Build the eq gadget inputs.
        let neg_output_activator = output_poly
            .mul_scalar_poly(-B::F::one())
            .add_scalar_poly(B::F::one());
        let eq_activator = match &shared_activator {
            Some(poly) => poly - &output_poly,
            None => neg_output_activator.clone(),
        };
        let eq_left = build_table_with_activator(&left_input, &eq_activator.clone());
        let eq_right = build_table_with_activator(&right_input, &eq_activator.clone());
        let mut eq_payload = match virtualized_ir.payload_for_node(&self.eq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        eq_payload.insert(eq::LEFT_LABEL.to_string(), eq_left);
        eq_payload.insert(eq::RIGHT_LABEL.to_string(), eq_right);
        virtualized_ir.set_payload_for_node(
            self.eq.id(),
            Some(PayloadStructure::GadgetPayload(eq_payload)),
        );

        // Build the neq gadget inputs.
        let neq_activator = output_poly.clone();
        let neq_left = build_table_with_activator(&left_input, &neq_activator.clone());
        let neq_right = build_table_with_activator(&right_input, &neq_activator.clone());
        let mut neq_payload = match virtualized_ir.payload_for_node(&self.neq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        neq_payload.insert(neq::LEFT_LABEL.to_string(), neq_left);
        neq_payload.insert(neq::RIGHT_LABEL.to_string(), neq_right);
        virtualized_ir.set_payload_for_node(
            self.neq.id(),
            Some(PayloadStructure::GadgetPayload(neq_payload)),
        );

        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_check.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), output);
        virtualized_ir.set_payload_for_node(
            self.bool_check.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::prover::irs::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for BinNeqNode<B> {
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
        // Fetch the payload for this gadget node.
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        // Extract the left, right, and output tracked tables from the payload.
        let (left_input, right_input, output) = match (
            gadget_payload.get(LEFT_INPUT_LABEL),
            gadget_payload.get(RIGHT_INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(left), Some(right), Some(output)) => {
                (left.clone(), right.clone(), output.clone())
            }
            _ => panic!("Expected left, right, and output tables for binary inequality gadget"),
        };

        // Ensure that the left and right inputs and output share the same activator oracle.
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Left and right inputs must share the same activator oracle"
        );
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            output.activator_tracked_poly(),
            "Left input and output must share the same activator oracle"
        );

        // Now that we are sure that the left and right inputs share the same activator oracle, we get this activator.
        let shared_activator = left_input.activator_tracked_poly();

        let output_ind = output.data_tracked_oracles_indices()[0];
        let output_oracle = output
            .tracked_col_oracle_by_ind(output_ind)
            .data_tracked_oracle();

        let build_table_with_activator =
            |table: &arithmetic::table_oracle::TrackedTableOracle<B>,
             activator: &ark_piop::verifier::structs::oracle::TrackedOracle<B>| {
                let mut oracles = IndexMap::new();
                for (field, oracle) in table.tracked_oracles_iter() {
                    if is_system_column(field.name()) {
                        continue;
                    }
                    oracles.insert(field.clone(), oracle.clone());
                }
                oracles.insert(ACTIVATOR_FIELD.clone(), activator.clone());

                let metadata = table
                    .schema_ref()
                    .map(|s| s.metadata().clone())
                    .unwrap_or_default();
                let fields = oracles
                    .keys()
                    .map(|f| f.as_ref().clone())
                    .collect::<Vec<_>>();
                let schema = Some(Schema::new_with_metadata(fields, metadata));

                let table_log_size = table.log_size();
                let activator_log_size = activator.log_size();
                let log_size = if table_log_size == 0 {
                    activator_log_size
                } else {
                    debug_assert_eq!(
                        table_log_size, activator_log_size,
                        "BinNeq gadget activator log size should match table log size"
                    );
                    table_log_size
                };
                arithmetic::table_oracle::TrackedTableOracle::new(schema, oracles, log_size)
            };

        // Build the eq gadget inputs.
        let neg_output_activator = output_oracle
            .mul_scalar_oracle(-B::F::one())
            .add_scalar_oracle(B::F::one());
        let eq_activator = match &shared_activator {
            Some(oracle) => oracle - &output_oracle,
            None => neg_output_activator.clone(),
        };
        let eq_left = build_table_with_activator(&left_input, &eq_activator);
        let eq_right = build_table_with_activator(&right_input, &eq_activator);
        let mut eq_payload = match virtualized_ir.payload_for_node(&self.eq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        eq_payload.insert(eq::LEFT_LABEL.to_string(), eq_left);
        eq_payload.insert(eq::RIGHT_LABEL.to_string(), eq_right);
        virtualized_ir.set_payload_for_node(
            self.eq.id(),
            Some(PayloadStructure::GadgetPayload(eq_payload)),
        );

        // Build the neq gadget inputs.
        let neq_activator = output_oracle.clone();
        let neq_left = build_table_with_activator(&left_input, &neq_activator);
        let neq_right = build_table_with_activator(&right_input, &neq_activator);
        let mut neq_payload = match virtualized_ir.payload_for_node(&self.neq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        neq_payload.insert(neq::LEFT_LABEL.to_string(), neq_left);
        neq_payload.insert(neq::RIGHT_LABEL.to_string(), neq_right);
        virtualized_ir.set_payload_for_node(
            self.neq.id(),
            Some(PayloadStructure::GadgetPayload(neq_payload)),
        );

        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_check.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), output);
        virtualized_ir.set_payload_for_node(
            self.bool_check.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::verifier::irs::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for BinNeqNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Fetch the payload for this gadget node.
        let gadget_payload = match gadget_ready_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        // Extract the left, right, and output tracked tables from the payload.
        let (left_input, right_input, output) = match (
            gadget_payload.get(LEFT_INPUT_LABEL),
            gadget_payload.get(RIGHT_INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(left), Some(right), Some(output)) => {
                (left.clone(), right.clone(), output.clone())
            }
            _ => panic!("Expected left, right, and output tables for binary inequality gadget"),
        };

        // Ensure that the left and right inputs and output share the same activator oracle.
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Left and right inputs must share the same activator oracle"
        );
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            output.activator_tracked_poly(),
            "Left input and output must share the same activator oracle"
        );

        // Now that we are sure that the left and right inputs share the same activator oracle, we get this activator.
        let shared_activator = left_input.activator_tracked_poly();
        let output_ind = output.data_tracked_polys_indices()[0];
        let output_poly = output.tracked_col_by_ind(output_ind).data_tracked_poly();

        if let Some(activator) = shared_activator {
            let zero_poly = &(activator.sub_scalar_poly(B::F::one())) * &output_poly;
            prover.add_mv_zerocheck_claim(zero_poly.id())?;
        };

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
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Fetch the payload for this gadget node.
        let gadget_payload = match gadget_ready_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        // Extract the left, right, and output tracked tables from the payload.
        let (left_input, right_input, output) = match (
            gadget_payload.get(LEFT_INPUT_LABEL),
            gadget_payload.get(RIGHT_INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(left), Some(right), Some(output)) => {
                (left.clone(), right.clone(), output.clone())
            }
            _ => panic!("Expected left, right, and output tables for binary inequality gadget"),
        };

        // Ensure that the left and right inputs and output share the same activator oracle.
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Left and right inputs must share the same activator oracle"
        );
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            output.activator_tracked_poly(),
            "Left input and output must share the same activator oracle"
        );

        // Now that we are sure that the left and right inputs share the same activator oracle, we get this activator.
        let shared_activator = left_input.activator_tracked_poly();
        let output_ind = output.data_tracked_oracles_indices()[0];
        let output_poly = output
            .tracked_col_oracle_by_ind(output_ind)
            .data_tracked_oracle();

        if let Some(activator) = shared_activator {
            let zero_poly = &(activator.sub_scalar_oracle(B::F::one())) * &output_poly;
            verifier.add_zerocheck_claim(zero_poly.id());
        };

        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for BinNeqNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> BinNeqNode<B> {
    pub fn new() -> Self
    where
        Self: Sized,
    {
        let col_eq_gadget = Arc::new(Node::<B>::Gadget(Arc::new(eq::GadgetNode::new())));
        let col_neq_gadget = Arc::new(Node::<B>::Gadget(Arc::new(neq::GadgetNode::new())));
        let bool_check_gadget = Arc::new(Node::<B>::Gadget(Arc::new(bool::GadgetNode::<B>::new())));
        Self {
            eq: col_eq_gadget,
            neq: col_neq_gadget,
            bool_check: bool_check_gadget,
        }
    }
}
