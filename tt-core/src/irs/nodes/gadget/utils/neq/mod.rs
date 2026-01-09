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
pub struct GadgetNode<B: SnarkBackend>(PhantomData<B>);

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Neq".to_string()
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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for neq gadget");
        };
        let (Some(left_input), Some(right_input)) = (
            payload.get(LEFT_LABEL).cloned(),
            payload.get(RIGHT_LABEL).cloned(),
        ) else {
            panic!("Expected left and right inputs for neq gadget");
        };

        let left_data_inds = left_input.data_tracked_polys_indices();
        let right_data_inds = right_input.data_tracked_polys_indices();
        debug_assert_eq!(
            left_data_inds.len(),
            right_data_inds.len(),
            "Neq gadget expects the same number of data columns on left and right."
        );
        for (left_data_ind, right_data_ind) in left_data_inds.iter().zip(right_data_inds.iter()) {
            let left_col = left_input.tracked_col_by_ind(*left_data_ind);
            let right_col = right_input.tracked_col_by_ind(*right_data_ind);
            let non_zero_poly =
                &left_col.activated_data_tracked_poly() - &right_col.activated_data_tracked_poly();
            let nozercheck_piop_prover_input = NoZerosCheckProverInput {
                col: TrackedCol::new(non_zero_poly, left_col.activator_tracked_poly(), None),
            };
            NoZerosCheck::prove(prover, nozercheck_piop_prover_input)?;
        }
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
            panic!("Expected gadget payload for neq gadget");
        };
        let (Some(left_input), Some(right_input)) = (
            payload.get(LEFT_LABEL).cloned(),
            payload.get(RIGHT_LABEL).cloned(),
        ) else {
            panic!("Expected left and right inputs for neq gadget");
        };

        let left_data_inds = left_input.data_tracked_oracles_indices();
        let right_data_inds = right_input.data_tracked_oracles_indices();
        debug_assert_eq!(
            left_data_inds.len(),
            right_data_inds.len(),
            "Neq gadget expects the same number of data columns on left and right."
        );
        for (left_data_ind, right_data_ind) in left_data_inds.iter().zip(right_data_inds.iter()) {
            let left_col = left_input.tracked_col_oracle_by_ind(*left_data_ind);
            let right_col = right_input.tracked_col_oracle_by_ind(*right_data_ind);
            let non_zero_oracle = &left_col.activated_data_tracked_oracle()
                - &right_col.activated_data_tracked_oracle();
            let nozercheck_piop_verifier_input = NoZerosCheckVerifierInput {
                tracked_col_oracle: TrackedColOracle::new(
                    non_zero_oracle,
                    left_col.activator_tracked_oracle(),
                    None,
                ),
            };
            NoZerosCheck::verify(verifier, nozercheck_piop_verifier_input)?;
        }
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
    pub fn new() -> Self
    where
        Self: Sized,
    {
        Self(PhantomData)
    }
}
