use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable};
use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, Node,
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
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Fetch the gadget payload populated by the parent plan node.
        let gadget_payload = match virtualized_ir.payload_for_node(&_id) {
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
        let input_act_poly = input_act.activator_tracked_poly();
        let predicate_poly = predicate
            .tracked_polys_iter()
            .find_map(|(field, poly)| (field.name() != ACTIVATOR_COL_NAME).then(|| poly.clone()));
        let left_field = input_act
            .tracked_polys_iter()
            .next()
            .map(|(field, _)| field.clone());

        let (Some(input_act_poly), Some(predicate_poly), Some(field_ref)) =
            (input_act_poly, predicate_poly, left_field)
        else {
            return Ok(());
        };

        let left_poly = &input_act_poly * &predicate_poly;
        let mut left_polys = IndexMap::new();
        left_polys.insert(field_ref, left_poly);
        let left_table = TrackedTable::new(input_act.schema(), left_polys, input_act.log_size());

        // Populate the col_eq gadget inputs.
        let mut col_eq_payload = match virtualized_ir.payload_for_node(&self.col_eq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
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
}
