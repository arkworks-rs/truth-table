use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_piop::SnarkBackend;
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

pub struct GadgetNode<B: SnarkBackend>(PhantomData<B>);

fn folding_challenges<F: PrimeField>(count: usize) -> Vec<F> {
    (0..count).map(|i| F::from((i + 1) as u64)).collect()
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Eq".to_string()
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

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
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
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
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
        let left_data_inds = left_input.data_tracked_polys_indices();
        let right_data_inds = right_input.data_tracked_polys_indices();
        debug_assert_eq!(
            left_data_inds.len(),
            right_data_inds.len(),
            "Eq gadget expects the same number of data columns on left and right."
        );
        debug_assert!(
            !left_data_inds.is_empty(),
            "Eq gadget expects at least one data column per input."
        );
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Eq gadget expects the same activator for the left and right inputs, since they should be activated on the same rows."
        );
        let activator = left_input.activator_tracked_poly();
        let challenges = folding_challenges::<B::F>(left_data_inds.len());
        let left_col = left_input.fold_all_data_columns(&challenges);
        let right_col = right_input.fold_all_data_columns(&challenges);
        // Form the polynomial that should be zero if the two folded table views are equal
        let zero_poly = match activator {
            Some(activator_tracked_poly) => {
                &(&left_col.data_tracked_poly() - &right_col.data_tracked_poly())
                    * &activator_tracked_poly
            }
            None => &left_col.data_tracked_poly() - &right_col.data_tracked_poly(),
        };
        // Emit the zero-check claim for this polynomial
        prover.add_mv_zerocheck_claim(zero_poly.id())?;
        Ok(())
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
        let left_data_inds = left_input.data_tracked_oracles_indices();
        let right_data_inds = right_input.data_tracked_oracles_indices();
        debug_assert_eq!(
            left_data_inds.len(),
            right_data_inds.len(),
            "Eq gadget expects the same number of data columns on left and right."
        );
        debug_assert!(
            !left_data_inds.is_empty(),
            "Eq gadget expects at least one data column per input."
        );
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Eq gadget expects the same activator for the left and right inputs, since they should be activated on the same rows."
        );
        let activator = left_input.activator_tracked_poly();
        let challenges = folding_challenges::<B::F>(left_data_inds.len());
        let left_col = left_input.fold_all_data_oracles(&challenges);
        let right_col = right_input.fold_all_data_oracles(&challenges);
        // Form the oracle that should be zero if the two folded table views are equal.
        let zero_oracle = match activator {
            Some(activator_tracked_poly) => {
                &(&left_col.data_tracked_oracle() - &right_col.data_tracked_oracle())
                    * &activator_tracked_poly
            }
            None => &left_col.data_tracked_oracle() - &right_col.data_tracked_oracle(),
        };
        // Emit the zero-check claim for this oracle.
        verifier.add_zerocheck_claim(zero_oracle.id());
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
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
        Self(PhantomData)
    }
}
