use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, IsTable};
use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, Node, NodeVirtualWitnessOps,
    gadget::{GadgetAncestry, utils::eq},
};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;

pub const INPUT_ACTIVATOR_LABEL: &str = "__input_activator__";
pub const OUTPUT_ACTIVATOR_LABEL: &str = "__output_activator__";
pub const FILTER_PREDICATE_LABEL: &str = "__filter_predicate__";

pub struct ProverNode<B: SnarkBackend> {
    col_eq: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Filter".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.col_eq.clone()]
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
        // Fetch the gadget payload populated by the parent plan node.
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };

        let (input_act, output_act, predicate) = match (
            gadget_payload.get(INPUT_ACTIVATOR_LABEL),
            gadget_payload.get(OUTPUT_ACTIVATOR_LABEL),
            gadget_payload.get(FILTER_PREDICATE_LABEL),
        ) {
            (Some(input), Some(output), Some(pred)) => {
                (input.clone(), output.clone(), pred.clone())
            }
            _ => return Ok(()),
        };

        // Extract the activator polynomial from the input and the predicate polynomial
        // (the first non-activator column) to build the left input.
        let input_act_poly = input_act
            .columns_iter()
            .find_map(|(field, poly)| (field.name() != ACTIVATOR_COL_NAME).then(|| poly.clone()));
        let predicate_poly = predicate
            .columns_iter()
            .find_map(|(field, poly)| (field.name() != ACTIVATOR_COL_NAME).then(|| poly.clone()));
        let left_field = input_act
            .columns_iter()
            .find_map(|(field, _)| (field.name() != ACTIVATOR_COL_NAME).then(|| field.clone()));

        let (Some(input_act_poly), Some(predicate_poly), Some(field_ref)) =
            (input_act_poly, predicate_poly, left_field)
        else {
            return Ok(());
        };

        let left_poly = T::mul_columns(&input_act_poly, &predicate_poly);
        let mut left_polys = IndexMap::new();
        left_polys.insert(field_ref, left_poly);
        let left_table = T::new_with(input_act.schema(), left_polys, input_act.log_size());

        // Populate the col_eq gadget inputs.
        let mut col_eq_payload = match virtualized_ir.payload_for_node(&self.col_eq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        // The right input is just the output activator.
        col_eq_payload.insert(eq::LEFT_LABEL.to_string(), left_table);
        col_eq_payload.insert(eq::RIGHT_LABEL.to_string(), output_act);

        virtualized_ir.set_payload_for_node(
            self.col_eq.id(),
            Some(PayloadStructure::GadgetPayload(col_eq_payload)),
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
        Self {
            col_eq: col_eq_gadget,
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
