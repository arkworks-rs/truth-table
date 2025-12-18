use std::{marker::PhantomData, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable};
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
        _id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let gadget_payload = match virtualized_ir.payload_for_node(&_id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };

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

        // Use the output column itself as the activator, but keep the activator
        // field from the left input to stay consistent with schema metadata.
        let output_poly = output
            .tracked_polys_iter()
            .next()
            .map(|(_, poly)| poly.clone());
        let activator_field = left_input
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, _)| field.clone());
        let Some((activator_field, activator_poly)) = activator_field.zip(output_poly) else {
            return Ok(());
        };

        let build_table_with_activator =
            |table: &TrackedTable<B>, activator: &(FieldRef, TrackedPoly<B>)| {
                let (act_field, act_poly) = activator;
                let mut polys = IndexMap::new();
                for (field, poly) in table.tracked_polys_iter() {
                    if field.name() == ACTIVATOR_COL_NAME {
                        continue;
                    }
                    polys.insert(field.clone(), poly.clone());
                }
                polys.insert(act_field.clone(), act_poly.clone());

                let metadata = table
                    .schema_ref()
                    .map(|s| s.metadata().clone())
                    .unwrap_or_default();
                let fields = polys.keys().map(|f| f.as_ref().clone()).collect::<Vec<_>>();
                let schema = Some(Schema::new_with_metadata(fields, metadata));

                TrackedTable::new(schema, polys, table.log_size())
            };

        let eq_left = build_table_with_activator(
            &left_input,
            &(activator_field.clone(), activator_poly.clone()),
        );
        let eq_right = build_table_with_activator(
            &right_input,
            &(activator_field.clone(), activator_poly.clone()),
        );

        let neg_output_activator = activator_poly
            .mul_scalar_poly(-B::F::one())
            .add_scalar_poly(B::F::one());
        let neq_left = build_table_with_activator(
            &left_input,
            &(activator_field.clone(), neg_output_activator.clone()),
        );
        let neq_right =
            build_table_with_activator(&right_input, &(activator_field, neg_output_activator));

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

        let mut neq_payload = match virtualized_ir.payload_for_node(&self.neq.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        neq_payload.insert(eq::LEFT_LABEL.to_string(), neq_left);
        neq_payload.insert(eq::RIGHT_LABEL.to_string(), neq_right);
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
