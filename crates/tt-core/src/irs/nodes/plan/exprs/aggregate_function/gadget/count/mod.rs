use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::irs::nodes::plan::exprs::aggregate_function::gadget::{
    INPUT_RLC_LABEL, OUTPUT_LABEL, OUTPUT_RLC_LABEL,
};
use crate::irs::nodes::utils::keyed_sumcheck::piop::{
    KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput,
};
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;
use ark_piop::piop::PIOP;

/// COUNT without groups: a keyed sumcheck of the constant key over the
/// input's active rows, each counted once, against the key on the output row
/// weighted by the count. With groups, COUNT is the lookup multiplicities and
/// this gadget gets no payload.
pub struct GadgetNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

macro_rules! count_tables {
    ($payload:expr) => {{
        let table = |label: &str| {
            $payload
                .get(label)
                .unwrap_or_else(|| panic!("Count Aggregate Function missing payload {label}"))
        };
        (
            table(INPUT_RLC_LABEL),
            table(OUTPUT_RLC_LABEL),
            table(OUTPUT_LABEL),
        )
    }};
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Count Aggregate Function".to_string()
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
            return Ok(());
        };
        let (input_key, output_key, count) = count_tables!(payload);
        let column = |table: &arithmetic::table::TrackedTable<B>| {
            table.tracked_col_by_ind(table.data_tracked_polys_indices()[0])
        };
        KeyedSumcheck::<B>::prove(
            prover,
            KeyedSumcheckProverInput {
                fxs: vec![column(input_key)],
                gxs: vec![column(output_key)],
                mfxs: vec![None],
                mgxs: vec![Some(column(count).data_tracked_poly())],
            },
        )
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (input_key, output_key, count) = count_tables!(payload);
        let column = |table: &arithmetic::table_oracle::TrackedTableOracle<B>| {
            table.tracked_col_oracle_by_ind(table.data_tracked_oracles_indices()[0])
        };
        KeyedSumcheck::<B>::verify(
            verifier,
            KeyedSumcheckVerifierInput {
                fxs: vec![column(input_key)],
                gxs: vec![column(output_key)],
                mfxs: vec![None],
                mgxs: vec![Some(column(count).data_tracked_oracle())],
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
