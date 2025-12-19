use std::{marker::PhantomData, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, table::TrackedTable};
use ark_ff::One;
use ark_piop::SnarkBackend;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use datafusion::arrow::datatypes::{FieldRef, Schema};
use datafusion_expr::Operator;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, IsPlanNode, Node,
    gadget::{
        GadgetAncestry,
        utils::{eq, neq},
    },
};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;

pub const LEFT_INPUT_LABEL: &str = "left_input";
pub const RIGHT_INPUT_LABEL: &str = "right_input";
pub const OUTPUT_LABEL: &str = "output";

pub struct ProverNode<B: SnarkBackend> {
    eq: Arc<Node<B>>,
    neq: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Binary Equality".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.eq.clone(), self.neq.clone()]
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
            _ => panic!("Expected left, right, and output tables for binary equality gadget"),
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

        // Build the eq gadget inputs
        let eq_activator = match &shared_activator {
            Some(poly) => poly * &output_poly,
            None => output_poly.clone(),
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

        // Build the neq gadget inputs
        let neg_output_activator = output_poly
            .mul_scalar_poly(-B::F::one())
            .add_scalar_poly(B::F::one());
        let neq_activator = match &shared_activator {
            Some(poly) => poly * &neg_output_activator,
            None => neg_output_activator.clone(),
        };
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
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for ProverNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // TODO: implement gadget proof
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn new() -> Self
    where
        Self: Sized,
    {
        let col_eq_gadget = Arc::new(Node::<B>::Gadget(Arc::new(eq::ProverNode::new())));
        let col_neq_gadget = Arc::new(Node::<B>::Gadget(Arc::new(neq::ProverNode::new())));
        Self {
            eq: col_eq_gadget,
            neq: col_neq_gadget,
        }
    }
}
