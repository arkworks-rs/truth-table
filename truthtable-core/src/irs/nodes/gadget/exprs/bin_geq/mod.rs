use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, table::TrackedTable};
use ark_ff::One;
use ark_piop::SnarkBackend;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
    gadget::utils::{eq, neq, sign},
};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub const LEFT_INPUT_LABEL: &str = "left_input";
pub const RIGHT_INPUT_LABEL: &str = "right_input";
pub const OUTPUT_LABEL: &str = "output";

pub struct BinQeqNode<B: SnarkBackend> {
    non_neg: Arc<Node<B>>,
    neg: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for BinQeqNode<B> {
    fn name(&self) -> String {
        "Binary GEQ".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.non_neg.clone(), self.neg.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for BinQeqNode<B> {
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
            _ => panic!("Expected left, right, and output tables for binary GEQ gadget"),
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
                if field.name() == ACTIVATOR_COL_NAME {
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

        // Compute the activator for the non_negative gadget
        let non_negative_activator = match &shared_activator {
            Some(poly) => poly * &output_poly,
            None => output_poly.clone(),
        };
        // Create the non_negative input table
        let non_negative_input =
            build_table_with_activator(&left_input, &non_negative_activator.clone());
        // Create the payload for the non_negative gadget node
        let non_negative_payload =
            IndexMap::from([(sign::INPUT_LABEL.to_string(), non_negative_input)]);
        // Set the payload for the non_negative gadget node
        virtualized_ir.set_payload_for_node(
            self.non_neg.id(),
            Some(PayloadStructure::GadgetPayload(non_negative_payload)),
        );

        // Compute the activator for the negative gadget
        let neg_output_activator = output_poly
            .mul_scalar_poly(-B::F::one())
            .add_scalar_poly(B::F::one());
        let negative_activator = match &shared_activator {
            Some(poly) => poly * &neg_output_activator,
            None => neg_output_activator.clone(),
        };
        // Create the negative input table
        let negative_input = build_table_with_activator(&left_input, &negative_activator.clone());
        // Create the payload for the negative gadget node
        let negative_payload = IndexMap::from([(sign::INPUT_LABEL.to_string(), negative_input)]);
        // Set the payload for the negative gadget node
        virtualized_ir.set_payload_for_node(
            self.neg.id(),
            Some(PayloadStructure::GadgetPayload(negative_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for BinQeqNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for BinQeqNode<B> {
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

impl<B: SnarkBackend> BinQeqNode<B> {
    fn new() -> Self
    where
        Self: Sized,
    {
        let col_non_neg_gadget = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::Sign::NonNegative,
        ))));
        let col_neg_gadget = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::Sign::Negative,
        ))));
        Self {
            neg: col_neg_gadget,
            non_neg: col_non_neg_gadget,
        }
    }
}
