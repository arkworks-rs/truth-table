//! Inequality gadget for table-shaped inputs.
//!
//! This module enforces inequality between two input tables on activated rows by:
//! 1. Folding all data columns on each side with random challenges.
//! 2. Subtracting folded right from folded left.
//! 3. Shifting non-activated rows with a verifier challenge so only activated
//!    rows are constrained to be non-zero.
//! 4. Emitting a non-zero-check claim in both prover and verifier flows.

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
use ark_ff::One;
use ark_ff::Zero;
use ark_piop::SnarkBackend;
use either::Either::{Left, Right};
use indexmap::IndexMap;

use std::marker::PhantomData;
/// Label for the left input to the neq gadget
pub const LEFT_LABEL: &str = "left";
/// Label for the right input to the neq gadget
pub const RIGHT_LABEL: &str = "right";

/// A gadget node that enforces that two tables are not equal on all activated rows.
pub struct GadgetNode<B: SnarkBackend>(PhantomData<B>);

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Neq".to_string()
    }

    fn display(&self) -> String {
        self.name()
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

        // Check that every activated row differs between left/right inputs.
        let left_data_inds = left_input.data_tracked_polys_indices();
        let right_data_inds = right_input.data_tracked_polys_indices();
        debug_assert_eq!(
            left_data_inds.len(),
            right_data_inds.len(),
            "Neq gadget expects the same number of data columns on left and right."
        );
        let mut challenges = Vec::with_capacity(left_data_inds.len());
        for _ in 0..left_data_inds.len() {
            challenges.push(prover.get_and_append_challenge(b"neq_fold")?);
        }
        let left_col = left_input.fold_all_data_columns(&challenges);
        let right_col = right_input.fold_all_data_columns(&challenges);
        let non_zero_poly = &left_col.data_tracked_poly() - &right_col.data_tracked_poly();
        let one_minus_non_zero_activator = match left_col.activator_tracked_poly() {
            Some(activator) => {
                (activator.mul_scalar_poly(-B::F::one())).add_scalar_poly(B::F::one())
            }
            None => non_zero_poly.mul_scalar_poly(B::F::zero()),
        };
        let chall = prover.get_and_append_challenge(b"neq")?;
        let non_zero_poly = &non_zero_poly + &one_minus_non_zero_activator.mul_scalar_poly(chall);
        match non_zero_poly.id_or_const() {
            Left(id) => prover.add_mv_nozerocheck_claim(id)?,
            Right(cnst) => assert!(
                !cnst.is_zero(),
                "Non-zero check on zero constant polynomial in neq gadget"
            ),
        }
        Ok(())
    }

    fn honest_prover_check(
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

        let left_data_inds = left_input.data_tracked_polys_indices();
        let right_data_inds = right_input.data_tracked_polys_indices();
        debug_assert_eq!(
            left_data_inds.len(),
            right_data_inds.len(),
            "Neq gadget expects the same number of data columns on left and right."
        );
        let mut challenges = Vec::with_capacity(left_data_inds.len());
        for _ in 0..left_data_inds.len() {
            challenges.push(prover.get_and_append_challenge(b"neq_fold")?);
        }
        let left_col = left_input.fold_all_data_columns(&challenges);
        let right_col = right_input.fold_all_data_columns(&challenges);
        let left_vals = left_col.data_tracked_poly().evaluations();
        let right_vals = right_col.data_tracked_poly().evaluations();
        let activator = left_col
            .activator_tracked_poly()
            .map(|poly| poly.evaluations());
        for (row_idx, (left_val, right_val)) in left_vals.iter().zip(right_vals.iter()).enumerate()
        {
            if let Some(act) = activator.as_ref()
                && act[row_idx] != B::F::one()
            {
                continue;
            }
            if left_val == right_val {
                // Activated rows must differ on the checked column.
                return Err(ark_piop::errors::SnarkError::ProverError(
                    ark_piop::prover::errors::ProverError::HonestProverError(
                        ark_piop::prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
            }
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
        let mut challenges = Vec::with_capacity(left_data_inds.len());
        for _ in 0..left_data_inds.len() {
            challenges.push(verifier.get_and_append_challenge(b"neq_fold")?);
        }
        let left_col = left_input.fold_all_data_oracles(&challenges);
        let right_col = right_input.fold_all_data_oracles(&challenges);
        let non_zero_oracle = &left_col.data_tracked_oracle() - &right_col.data_tracked_oracle();
        let one_minus_activator = match left_col.activator_tracked_oracle() {
            Some(activator) => activator
                .mul_scalar_oracle(-B::F::one())
                .add_scalar_oracle(B::F::one()),
            None => non_zero_oracle.mul_scalar_oracle(B::F::zero()),
        };
        let chall = verifier.get_and_append_challenge(b"neq")?;
        let non_zero_oracle = &non_zero_oracle + &one_minus_activator.mul_scalar_oracle(chall);
        match non_zero_oracle.id_or_const() {
            Left(id) => verifier.add_nozerocheck_claim(id),
            Right(cnst) => assert!(
                !cnst.is_zero(),
                "Non-zero check on zero constant polynomial in neq gadget"
            ),
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
