use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use super::bin_eq::{LEFT_INPUT_LABEL, OUTPUT_LABEL, RIGHT_INPUT_LABEL};
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

/// `left / right`: the materialized output is the truncated quotient
/// (`utils::division`).
pub struct BinDivNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> Default for BinDivNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> BinDivNode<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

macro_rules! division_operands {
    ($payload:expr, $polys:ident, $col_by_ind:ident, $data:ident) => {{
        let table = |label: &str| {
            $payload
                .get(label)
                .unwrap_or_else(|| panic!("Binary division gadget missing payload {label}"))
        };
        let column = |label: &str| {
            let table = table(label);
            let col = table.$col_by_ind(table.$polys()[0]);
            let field = col
                .field_ref()
                .expect("Division operand should carry a data field");
            (col.$data(), field)
        };
        (
            table(LEFT_INPUT_LABEL).activator_tracked_poly(),
            column(LEFT_INPUT_LABEL),
            column(RIGHT_INPUT_LABEL),
            column(OUTPUT_LABEL),
        )
    }};
}

impl<B: SnarkBackend> IsNode<B> for BinDivNode<B> {
    fn name(&self) -> String {
        "Binary DIV".to_string()
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

impl<B: SnarkBackend> ProverNodeOps<B> for BinDivNode<B> {
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

impl<B: SnarkBackend> VerifierNodeOps<B> for BinDivNode<B> {
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

impl<B: SnarkBackend> IsGadgetNode<B> for BinDivNode<B> {
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
        let (activator, (num, num_field), (den, den_field), (quot, quot_field)) = division_operands!(
            payload,
            data_tracked_polys_indices,
            tracked_col_by_ind,
            data_tracked_poly
        );
        division::prove(
            prover,
            activator.as_ref(),
            Operand {
                data: &num,
                data_type: num_field.data_type(),
            },
            Divisor::Column {
                operand: Operand {
                    data: &den,
                    data_type: den_field.data_type(),
                },
                positive: false,
            },
            Operand {
                data: &quot,
                data_type: quot_field.data_type(),
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
        let (activator, (num, num_field), (den, den_field), (quot, quot_field)) = division_operands!(
            payload,
            data_tracked_polys_indices,
            tracked_col_by_ind,
            data_tracked_poly
        );
        division::honest_check(
            activator.as_ref(),
            Operand {
                data: &num,
                data_type: num_field.data_type(),
            },
            Divisor::Column {
                operand: Operand {
                    data: &den,
                    data_type: den_field.data_type(),
                },
                positive: false,
            },
            Operand {
                data: &quot,
                data_type: quot_field.data_type(),
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
        let (activator, (num, num_field), (den, den_field), (quot, quot_field)) = division_operands!(
            payload,
            data_tracked_oracles_indices,
            tracked_col_oracle_by_ind,
            data_tracked_oracle
        );
        division::verify(
            verifier,
            activator.as_ref(),
            Operand {
                data: &num,
                data_type: num_field.data_type(),
            },
            Divisor::Column {
                operand: Operand {
                    data: &den,
                    data_type: den_field.data_type(),
                },
                positive: false,
            },
            Operand {
                data: &quot,
                data_type: quot_field.data_type(),
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
