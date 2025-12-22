use std::marker::PhantomData;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{SnarkBackend, piop::PIOP};
use col_toolbox::no_zeros_check::{
    NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput,
};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
pub const LEFT_LABEL: &str = "left";
pub const RIGHT_LABEL: &str = "right";
pub struct ProverNode<B: SnarkBackend>(PhantomData<B>);

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Neq".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
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
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
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
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for ProverNode<B> {
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
        let (Some(left_input), Some(right_input)) = (
            payload.get(LEFT_LABEL).cloned(),
            payload.get(RIGHT_LABEL).cloned(),
        ) else {
            return Ok(());
        };


        // Each of the left and right inputs should have exactly one data tracked polynomial, Because we are checking the equality of two columns
        debug_assert_eq!(
            left_input.data_tracked_polys_indices().len(),
            1,
            "Eq gadget supports one tracked polynomial per input."
        );
        debug_assert_eq!(
            right_input.data_tracked_polys_indices().len(),
            1,
            "Eq gadget supports one tracked polynomial per input."
        );
        // Extract the indices corresponding to the left and right data tracked polynomials
        let left_data_ind = left_input.data_tracked_polys_indices()[0];
        let right_data_ind = right_input.data_tracked_polys_indices()[0];
        // Fetch the tracked columns corresponding to those indices
        let left_col = left_input.tracked_col_by_ind(left_data_ind);
        let right_col = right_input.tracked_col_by_ind(right_data_ind);
        // Form the polynomial that should be zero if the two columns are equal
        let non_zero_poly =
            &left_col.activated_data_tracked_poly() - &right_col.activated_data_tracked_poly();
        // Invoke a NoZerosCheck on the resulting column
        let nozercheck_piop_prover_input = NoZerosCheckProverInput {
            col: TrackedCol::new(non_zero_poly, left_col.activator_tracked_poly(), None),
        };
        NoZerosCheck::prove(prover, nozercheck_piop_prover_input)?;
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
        let (Some(left_input), Some(right_input)) = (
            payload.get(LEFT_LABEL).cloned(),
            payload.get(RIGHT_LABEL).cloned(),
        ) else {
            return Ok(());
        };

        // Each of the left and right inputs should have exactly one data tracked oracle.
        debug_assert_eq!(
            left_input.data_tracked_oracles_indices().len(),
            1,
            "Eq gadget supports one tracked oracle per input."
        );
        debug_assert_eq!(
            right_input.data_tracked_oracles_indices().len(),
            1,
            "Eq gadget supports one tracked oracle per input."
        );
        // Extract the indices corresponding to the left and right data tracked oracles.
        let left_data_ind = left_input.data_tracked_oracles_indices()[0];
        let right_data_ind = right_input.data_tracked_oracles_indices()[0];
        // Fetch the tracked column oracles corresponding to those indices.
        let left_col = left_input.tracked_col_oracle_by_ind(left_data_ind);
        let right_col = right_input.tracked_col_oracle_by_ind(right_data_ind);
        // Form the oracle that should be non-zero when the columns differ.
        let non_zero_oracle =
            &left_col.activated_data_tracked_oracle() - &right_col.activated_data_tracked_oracle();
        // Invoke a NoZerosCheck on the resulting oracle.
        let nozercheck_piop_verifier_input = NoZerosCheckVerifierInput {
            tracked_col_oracle: TrackedColOracle::new(
                non_zero_oracle,
                left_col.activator_tracked_oracle(),
                None,
            ),
        };
        NoZerosCheck::verify(verifier, nozercheck_piop_verifier_input)?;
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn new() -> Self
    where
        Self: Sized,
    {
        Self(PhantomData)
    }
}
