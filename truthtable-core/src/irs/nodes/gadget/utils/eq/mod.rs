use std::marker::PhantomData;

use ark_piop::SnarkBackend;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, NodeVirtualWitnessOps, ProverNodeOps},
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
        "Eq".to_string()
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
    fn add_virtual_witness_generic<T>(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::irs::shared_ir::VirtualizedIr<B, T>,
    ) -> ark_piop::errors::SnarkResult<()>
    where
        T: IsTable,
        T::Column: Clone,
    {
        Ok(())
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {


    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
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
        // First fetch the payloads prepared for this gadget to consume
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Eq gadget node");
        };
        // Then inside that payload, fetch the left and right inputs
        let (Some(left_input), Some(right_input)) = (
            payload.get(LEFT_LABEL).cloned(),
            payload.get(RIGHT_LABEL).cloned(),
        ) else {
            panic!("Expected left and right inputs for Eq gadget");
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
        let zero_poly =
            &left_col.activated_data_tracked_poly() - &right_col.activated_data_tracked_poly();
        // Emit the zero-check claim for this polynomial
        prover.add_mv_zerocheck_claim(zero_poly.id())?;
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
