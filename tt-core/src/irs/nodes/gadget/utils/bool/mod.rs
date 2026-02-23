use std::marker::PhantomData;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    errors::SnarkError,
    prover::errors::{HonestProverError, ProverError},
    verifier::errors::VerifierError,
};
use indexmap::IndexMap;
use std::ops::Neg;
pub const TABLE_LABEL: &str = "__table__";

pub struct GadgetNode<B: SnarkBackend>(PhantomData<B>);

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Bool".to_string()
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
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
            panic!("Expected gadget payload for Bool gadget node");
        };
        let Some(table) = payload.get(TABLE_LABEL).cloned() else {
            panic!("Expected table payload for Bool gadget");
        };

        for idx in table.data_tracked_polys_indices() {
            let col = table.tracked_col_by_ind(idx);
            // BinaryCheck only needs the predicate polynomial, so we pass the activated column.
            let predicate_data = col.data_tracked_poly();
            let predicate_activator = col.activator_tracked_poly();
            let one_minus_data = predicate_data
                .mul_scalar_poly(B::F::one().neg())
                .add_scalar_poly(B::F::one());
            let check_poly = match predicate_activator {
                Some(actv) => &(&predicate_data * &one_minus_data) * &actv,
                None => &predicate_data * &one_minus_data,
            };

            match check_poly.id_or_const() {
                either::Either::Left(id) => {
                    prover.add_mv_zerocheck_claim(id)?;
                }
                either::Either::Right(cnst) => {
                    if !cnst.is_zero() {
                        return Err(SnarkError::ProverError(ProverError::HonestProverError(
                            HonestProverError::FalseClaim,
                        )));
                    }
                }
            }
        }
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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Bool gadget node");
        };
        let Some(table) = payload.get(TABLE_LABEL).cloned() else {
            panic!("Expected table payload for Bool gadget");
        };

        for idx in table.data_tracked_oracles_indices() {
            let col = table.tracked_col_oracle_by_ind(idx);
            // BinaryCheck only needs the predicate oracle, so we pass the activated column.
            let predicate_data = col.data_tracked_oracle();
            let predicate_activator = col.activator_tracked_oracle();
            let one_minus_data = predicate_data
                .mul_scalar_oracle(B::F::one().neg())
                .add_scalar_oracle(B::F::one());
            let check_poly = match predicate_activator {
                Some(actv) => &(&predicate_data * &one_minus_data) * &actv,
                None => &predicate_data * &one_minus_data,
            };
            match check_poly.id_or_const() {
                either::Either::Left(id) => {
                    verifier.add_zerocheck_claim(id);
                }
                either::Either::Right(cnst) => {
                    if !cnst.is_zero() {
                        return Err(SnarkError::VerifierError(
                            VerifierError::VerifierCheckFailed(
                                "Bool check failed: constant predicate is not boolean".to_string(),
                            ),
                        ));
                    }
                }
            }
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
    pub fn new() -> Self {
        Self(PhantomData)
    }
}
