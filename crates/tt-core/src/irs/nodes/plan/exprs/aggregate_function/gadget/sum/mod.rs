use std::sync::Arc;

use ark_piop::{SnarkBackend, errors::SnarkResult};
use datafusion::arrow::datatypes::DataType;
use indexmap::IndexMap;

use crate::irs::nodes::plan::exprs::aggregate_function::gadget::{
    INPUT_RLC_LABEL, OUTPUT_LABEL, OUTPUT_RLC_LABEL, input_label,
};
use crate::irs::nodes::utils::bounds::{Bound, check};
use crate::irs::nodes::utils::keyed_sumcheck;
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

/// The keyed sumcheck proves the sums; this range-checks each against the
/// output type (`bounds::check`), so a SUM is as safe an operand as a
/// column.
pub struct GadgetNode<B: SnarkBackend> {
    keyed_sumcheck: Arc<Node<B>>,
}

/// The input type and domain size, and the output's activator, column and
/// type.
macro_rules! sum_operands {
    ($payload:expr, $polys:ident, $col_by_ind:ident, $data:ident) => {{
        let table = |label: &str| {
            $payload
                .get(label)
                .unwrap_or_else(|| panic!("Sum Aggregate Function missing payload {label}"))
        };
        let input = table(&input_label(0));
        let output = table(OUTPUT_LABEL);
        let input_col = input.$col_by_ind(input.$polys()[0]);
        let out_col = output.$col_by_ind(output.$polys()[0]);
        let field_type = |field: Option<datafusion::arrow::datatypes::FieldRef>| {
            field
                .expect("SUM operand should carry a data field")
                .data_type()
                .clone()
        };
        (
            field_type(input_col.field_ref()),
            input.log_size(),
            output.activator_tracked_poly(),
            out_col.$data(),
            field_type(out_col.field_ref()),
        )
    }};
}

/// Bounds the sum by the argument's type. An argument past its type is one
/// `bounds::plan` left unchecked, which it does only when its own bound
/// passes this test.
fn ensure_fits_field<B: SnarkBackend>(input_type: &DataType, log_size: usize) -> SnarkResult<()> {
    Bound::of_type(input_type)?
        .sum(log_size)
        .ensure_fits_field::<B::F>(&format!("SUM of {input_type} over 2^{log_size} rows"))
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

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        let input_0_label = input_label(0);
        let (input_rlc, output_rlc, output_table, input_0) =
            {
                let Some(PayloadStructure::GadgetPayload(payload)) =
                    virtualized_ir.payload_for_node(&id)
                else {
                    panic!("Expected gadget payload for Sum Aggregate Function gadget");
                };

                (
                    payload.get(INPUT_RLC_LABEL).cloned().unwrap_or_else(|| {
                        panic!("Sum Aggregate Function missing input rlc payload")
                    }),
                    payload.get(OUTPUT_RLC_LABEL).cloned().unwrap_or_else(|| {
                        panic!("Sum Aggregate Function missing output rlc payload")
                    }),
                    payload
                        .get(OUTPUT_LABEL)
                        .cloned()
                        .unwrap_or_else(|| panic!("Sum Aggregate Function missing output payload")),
                    payload.get(&input_0_label).cloned().unwrap_or_else(|| {
                        panic!("Sum Aggregate Function missing payload {}", input_0_label)
                    }),
                )
            };

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

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (input_type, log_size, activator, out, out_type) = sum_operands!(
            payload,
            data_tracked_polys_indices,
            tracked_col_by_ind,
            data_tracked_poly
        );
        ensure_fits_field::<B>(&input_type, log_size)?;
        check::prove(prover, activator.as_ref(), &out, &out_type)
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (input_type, log_size, activator, out, out_type) = sum_operands!(
            payload,
            data_tracked_polys_indices,
            tracked_col_by_ind,
            data_tracked_poly
        );
        ensure_fits_field::<B>(&input_type, log_size)?;
        check::honest_check(activator.as_ref(), &out, &out_type, &self.name())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (input_type, log_size, activator, out, out_type) = sum_operands!(
            payload,
            data_tracked_oracles_indices,
            tracked_col_oracle_by_ind,
            data_tracked_oracle
        );
        ensure_fits_field::<B>(&input_type, log_size)?;
        check::verify(verifier, activator.as_ref(), &out, &out_type)
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
        let keyed_sumcheck_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            keyed_sumcheck::GadgetNode::new(),
        )));
        Self {
            keyed_sumcheck: keyed_sumcheck_gadget,
        }
    }
}

#[cfg(test)]
mod tests;
