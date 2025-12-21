use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, IsPlanNode, Node, NodeVirtualWitnessOps,
    gadget::{
        GadgetAncestry,
        utils::{eq, neq},
    },
};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use arithmetic::IsTable;

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
}

impl<B: SnarkBackend> NodeVirtualWitnessOps<B> for ProverNode<B> {
    fn add_virtual_witness<T>(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::irs::shared_ir::VirtualizedIr<B, T>,
    ) -> ark_piop::errors::SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone,
    {
        Ok(())
    }

    fn initialize_gadgets<T>(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::irs::shared_ir::VirtualizedIr<B, T>,
    ) -> ark_piop::errors::SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone,
    {
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
            _ => return Ok(()),
        };

        // Shared activator for left/right/output when present.
        let shared_activator = left_input.activator_column();

        let output_ind = match output.data_columns_indices().get(0) {
            Some(idx) => *idx,
            None => return Ok(()),
        };
        let output_poly = match output.columns().get_index(output_ind) {
            Some((_, poly)) => poly.clone(),
            None => return Ok(()),
        };

        let build_table_with_activator = |table: &T, activator: &T::Column| {
            let mut polys = IndexMap::new();
            for (field, poly) in table.columns_iter() {
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

            T::new_with(schema, polys, table.log_size())
        };

        // Build the eq gadget inputs
        let eq_activator = match &shared_activator {
            Some(poly) => T::mul_columns(poly, &output_poly),
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
        let mut neg_output_activator = T::mul_column_scalar(&output_poly, T::scalar_neg_one());
        neg_output_activator = T::add_column_scalar(&neg_output_activator, T::scalar_one());
        let neq_activator = match &shared_activator {
            Some(poly) => T::mul_columns(poly, &neg_output_activator),
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

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut crate::verifier::irs::GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // TODO: implement gadget verification
        Ok(())
    }
}
