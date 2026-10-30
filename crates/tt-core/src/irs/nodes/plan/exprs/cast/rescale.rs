use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::DataType;
use indexmap::IndexMap;

use super::Rescale;
use crate::irs::nodes::NodeId;
use crate::irs::nodes::cost::ProvingCost;
use crate::irs::nodes::hints::HintDF;
use crate::irs::nodes::utils::division::{self, Divisor, Operand};
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::{
    GadgetReadyIr as ProverGadgetReadyIr, VirtualizedIr as ProverVirtualizedIr,
};
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub(super) const INPUT_LABEL: &str = "__input__";
pub(super) const OUTPUT_LABEL: &str = "__output__";

/// The committed output of a cast that divides by `10^k`. A cast that does
/// not gives this gadget no payload.
pub struct RescaleNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> RescaleNode<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

/// The input's activator, then the input and the output with their types.
macro_rules! rescale_operands {
    ($payload:expr, $polys:ident, $col_by_ind:ident, $data:ident) => {{
        let column = |label: &str| {
            let table = $payload
                .get(label)
                .unwrap_or_else(|| panic!("Cast rescale gadget missing payload {label}"));
            let col = table.$col_by_ind(table.$polys()[0]);
            let field = col.field_ref().expect("a cast's columns are typed");
            (col.$data(), field)
        };
        (
            $payload[INPUT_LABEL].activator_tracked_poly(),
            column(INPUT_LABEL),
            column(OUTPUT_LABEL),
        )
    }};
}

fn rounding(input: &DataType, output: &DataType) -> division::Rounding {
    match super::rescale(input, output) {
        Some(Rescale::Down(rounding)) => rounding,
        _ => panic!("only a cast that divides has a rescale payload"),
    }
}

impl<B: SnarkBackend> IsNode<B> for RescaleNode<B> {
    fn name(&self) -> String {
        "Cast Rescale".to_string()
    }

    fn display(&self) -> String {
        let name = self.name();
        crate::irs::nodes::display_with_inputs(&name, &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for RescaleNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for RescaleNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for RescaleNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut ProverGadgetReadyIr<B>,
        id: NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (activator, (input, input_field), (output, output_field)) = rescale_operands!(
            payload,
            data_tracked_polys_indices,
            tracked_col_by_ind,
            data_tracked_poly
        );
        division::prove(
            prover,
            activator.as_ref(),
            Operand {
                data: &input,
                data_type: input_field.data_type(),
            },
            Divisor::Power10(rounding(input_field.data_type(), output_field.data_type())),
            Operand {
                data: &output,
                data_type: output_field.data_type(),
            },
        )
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut ProverGadgetReadyIr<B>,
        id: NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (activator, (input, input_field), (output, output_field)) = rescale_operands!(
            payload,
            data_tracked_polys_indices,
            tracked_col_by_ind,
            data_tracked_poly
        );
        division::honest_check(
            activator.as_ref(),
            Operand {
                data: &input,
                data_type: input_field.data_type(),
            },
            Divisor::Power10(rounding(input_field.data_type(), output_field.data_type())),
            Operand {
                data: &output,
                data_type: output_field.data_type(),
            },
        )
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (activator, (input, input_field), (output, output_field)) = rescale_operands!(
            payload,
            data_tracked_oracles_indices,
            tracked_col_oracle_by_ind,
            data_tracked_oracle
        );
        division::verify(
            verifier,
            activator.as_ref(),
            Operand {
                data: &input,
                data_type: input_field.data_type(),
            },
            Divisor::Power10(rounding(input_field.data_type(), output_field.data_type())),
            Operand {
                data: &output,
                data_type: output_field.data_type(),
            },
        )
    }

    fn prover_hints(&self) -> IndexMap<String, HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, HintDF> {
        IndexMap::new()
    }
}
