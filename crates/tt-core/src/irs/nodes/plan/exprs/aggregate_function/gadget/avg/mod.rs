use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::plan::exprs::aggregate_function::gadget::OUTPUT_LABEL;
use crate::irs::nodes::utils::division::{self, Operand};
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

/// The output-domain SUM and COUNT columns of the AVG's argument.
pub const SUM_LABEL: &str = "__avg-sum__";
pub const COUNT_LABEL: &str = "__avg-count__";

/// `avg = trunc(sum / count)` row by row on the aggregate's output
/// (`utils::division`); SUM and COUNT carry their own checks. COUNT is at
/// least 1 on every group, so its sign is not committed.
pub struct GadgetNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

macro_rules! avg_operands {
    ($payload:expr, $polys:ident, $col_by_ind:ident, $data:ident) => {{
        let table = |label: &str| {
            $payload
                .get(label)
                .unwrap_or_else(|| panic!("Avg Aggregate Function missing payload {label}"))
        };
        let column = |label: &str| {
            let table = table(label);
            let col = table.$col_by_ind(table.$polys()[0]);
            let field = col
                .field_ref()
                .expect("AVG operand should carry a data field");
            (col.$data(), field)
        };
        (
            table(OUTPUT_LABEL).activator_tracked_poly(),
            column(SUM_LABEL),
            column(COUNT_LABEL),
            column(OUTPUT_LABEL),
        )
    }};
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Avg Aggregate Function".to_string()
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
        vec![]
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
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Avg Aggregate Function gadget");
        };
        let (activator, (sum, sum_field), (count, count_field), (avg, avg_field)) = avg_operands!(
            payload,
            data_tracked_polys_indices,
            tracked_col_by_ind,
            data_tracked_poly
        );
        division::prove(
            prover,
            activator.as_ref(),
            Operand {
                data: &sum,
                data_type: sum_field.data_type(),
            },
            Operand {
                data: &count,
                data_type: count_field.data_type(),
            },
            true,
            Operand {
                data: &avg,
                data_type: avg_field.data_type(),
            },
        )
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (activator, (sum, sum_field), (count, count_field), (avg, avg_field)) = avg_operands!(
            payload,
            data_tracked_polys_indices,
            tracked_col_by_ind,
            data_tracked_poly
        );
        division::honest_check(
            activator.as_ref(),
            Operand {
                data: &sum,
                data_type: sum_field.data_type(),
            },
            Operand {
                data: &count,
                data_type: count_field.data_type(),
            },
            true,
            Operand {
                data: &avg,
                data_type: avg_field.data_type(),
            },
        )
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Avg Aggregate Function gadget");
        };
        let (activator, (sum, sum_field), (count, count_field), (avg, avg_field)) = avg_operands!(
            payload,
            data_tracked_oracles_indices,
            tracked_col_oracle_by_ind,
            data_tracked_oracle
        );
        division::verify(
            verifier,
            activator.as_ref(),
            Operand {
                data: &sum,
                data_type: sum_field.data_type(),
            },
            Operand {
                data: &count,
                data_type: count_field.data_type(),
            },
            true,
            Operand {
                data: &avg,
                data_type: avg_field.data_type(),
            },
        )
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
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}
