use std::marker::PhantomData;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{SnarkBackend, piop::PIOP};
use col_toolbox::no_zeros_check::{
    NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput,
};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, NodeVirtualWitnessOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
};
use arithmetic::IsTable;
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
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::irs::shared_ir::VirtualizedIr<B, T>,
    ) -> ark_piop::errors::SnarkResult<()>
    where
        T: IsTable<Scalar = <B as SnarkBackend>::F>,
        T::Column: Clone,
    {
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

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn new() -> Self
    where
        Self: Sized,
    {
        Self(PhantomData)
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut crate::verifier::irs::GadgetReadyIr<B>,
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

        let mut left_data_inds = left_input.data_tracked_oracles_indices();
        if left_data_inds.is_empty() && left_input.num_total_tracked_col_oracles() > 0 {
            left_data_inds.push(0);
        }
        let mut right_data_inds = right_input.data_tracked_oracles_indices();
        if right_data_inds.is_empty() && right_input.num_total_tracked_col_oracles() > 0 {
            right_data_inds.push(0);
        }
        if left_data_inds.is_empty() || right_data_inds.is_empty() {
            return Ok(());
        }
        debug_assert_eq!(
            left_data_inds.len(),
            1,
            "Neq gadget supports one tracked oracle per input."
        );
        debug_assert_eq!(
            right_data_inds.len(),
            1,
            "Neq gadget supports one tracked oracle per input."
        );
        let left_data_ind = left_data_inds[0];
        let right_data_ind = right_data_inds[0];
        let left_col = left_input.tracked_col_oracle_by_ind(left_data_ind);
        let right_col = right_input.tracked_col_oracle_by_ind(right_data_ind);
        let non_zero_oracle = &left_col.activated_data_tracked_oracle()
            - &right_col.activated_data_tracked_oracle();
        let nozero_oracle = TrackedColOracle::new(
            non_zero_oracle,
            left_col.activator_tracked_oracle(),
            None,
        );
        let nozerocheck_piop_verifier_input = NoZerosCheckVerifierInput {
            tracked_col_oracle: nozero_oracle,
        };
        NoZerosCheck::verify(verifier, nozerocheck_piop_verifier_input)?;
        Ok(())
    }
}
