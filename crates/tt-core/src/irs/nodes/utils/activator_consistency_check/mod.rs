//! A gadget node for paper §4.2 Activator Consistency Check.
//!
//! Given a char-level column `src` with activator `ac`, and a string-level
//! column `ind` with activator `ah` alongside a length column `l`, the
//! gadget proves for every string row `i`:
//!
//!     #{ c : src[c] = ind[i], ac[c] = 1 } = ah[i] · l[i]
//!
//! Payload structure:
//! - `LHS_LABEL` (`"__lhs__"`) — char-level table with a single data column
//!   holding `src`. The table's activator column is `ac`.
//! - `RHS_LABEL` (`"__rhs__"`) — string-level table with two data columns
//!   in insertion order: `ind` (index 0) and `l` (index 1). The table's
//!   activator column is `ah`.
//!
//! The gadget reduces to a single [`col_toolbox::keyed_sumcheck::KeyedSumcheck`]
//! invocation at a random challenge `γ`, forcing the two multiplicity
//! vectors (indexed by key) to agree row-wise via Schwartz–Zippel. `ind`
//! must be distinct across active string rows — a well-formedness
//! precondition on the caller (the natural instantiation is the identity
//! polynomial).
use std::marker::PhantomData;

use ark_piop::SnarkBackend;
use col_toolbox::keyed_sumcheck::{
    KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput,
};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
use ark_piop::{errors::SnarkResult, piop::PIOP};

pub const LHS_LABEL: &str = "__lhs__";
pub const RHS_LABEL: &str = "__rhs__";

/// Gadget node for the activator-consistency relation.
pub struct GadgetNode<B: SnarkBackend>(PhantomData<B>);

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

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "ActivatorConsistencyCheck".to_string()
    }

    fn display(&self) -> String {
        crate::irs::nodes::display_with_inputs(&self.name(), &self.children())
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
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let (src_col, ind_col, length_poly) = payload_prover(gadget_ready_ir, id);
        KeyedSumcheck::<B>::prove(
            prover,
            KeyedSumcheckProverInput {
                fxs: vec![src_col],
                gxs: vec![ind_col],
                mfxs: vec![None],
                mgxs: vec![Some(length_poly)],
            },
        )
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        use ark_ff::Zero;
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let (src_col, ind_col, length_poly) = payload_prover(gadget_ready_ir, id);

        let src_data = src_col.data_tracked_poly().evaluations();
        let src_act = src_col
            .activator_tracked_poly()
            .map(|a| a.evaluations());
        let ind_data = ind_col.data_tracked_poly().evaluations();
        let ind_act = ind_col
            .activator_tracked_poly()
            .map(|a| a.evaluations());
        let length_evals = length_poly.evaluations();

        // LHS: per src-key active-char count.
        let mut lhs_counts: IndexMap<B::F, u64> = IndexMap::with_capacity(src_data.len());
        for (c, &src_c) in src_data.iter().enumerate() {
            let active = src_act.as_ref().map(|a| !a[c].is_zero()).unwrap_or(true);
            if !active {
                continue;
            }
            *lhs_counts.entry(src_c).or_insert(0) += 1;
        }

        // RHS: per ind-key expected count = l[i] when ah[i]=1, 0 otherwise.
        let mut rhs_counts: IndexMap<B::F, B::F> = IndexMap::with_capacity(ind_data.len());
        for (i, (&ind_i, &l_i)) in ind_data.iter().zip(length_evals.iter()).enumerate() {
            let active = ind_act.as_ref().map(|a| !a[i].is_zero()).unwrap_or(true);
            if !active {
                continue;
            }
            let entry = rhs_counts.entry(ind_i).or_insert_with(B::F::zero);
            *entry += l_i;
        }

        let all_keys: indexmap::IndexSet<B::F> = lhs_counts
            .keys()
            .chain(rhs_counts.keys())
            .copied()
            .collect();
        for key in all_keys {
            let lhs = B::F::from(*lhs_counts.get(&key).unwrap_or(&0));
            let rhs = *rhs_counts.get(&key).unwrap_or(&B::F::zero());
            if lhs != rhs {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let (src_col_oracle, ind_col_oracle, length_oracle) =
            payload_verifier(gadget_ready_ir, id);
        KeyedSumcheck::<B>::verify(
            verifier,
            KeyedSumcheckVerifierInput {
                fxs: vec![src_col_oracle],
                gxs: vec![ind_col_oracle],
                mfxs: vec![None],
                mgxs: vec![Some(length_oracle)],
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

fn payload_prover<B: SnarkBackend>(
    gadget_ready_ir: &GadgetReadyIr<B>,
    id: NodeId,
) -> (
    arithmetic::col::TrackedCol<B>,
    arithmetic::col::TrackedCol<B>,
    ark_piop::prover::structs::polynomial::TrackedPoly<B>,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
    else {
        panic!("Expected gadget payload for ActivatorConsistencyCheck gadget node");
    };
    let lhs = payload
        .get(LHS_LABEL)
        .expect("ActivatorConsistencyCheck: missing LHS payload");
    let rhs = payload
        .get(RHS_LABEL)
        .expect("ActivatorConsistencyCheck: missing RHS payload");

    let lhs_indices = lhs.data_tracked_polys_indices();
    assert_eq!(
        lhs_indices.len(),
        1,
        "ActivatorConsistencyCheck LHS must have exactly one data column (src)"
    );
    let rhs_indices = rhs.data_tracked_polys_indices();
    assert_eq!(
        rhs_indices.len(),
        2,
        "ActivatorConsistencyCheck RHS must have exactly two data columns (ind, l)"
    );

    let src_col = lhs.tracked_col_by_ind(lhs_indices[0]);
    let ind_col = rhs.tracked_col_by_ind(rhs_indices[0]);
    let length_poly = rhs.tracked_col_by_ind(rhs_indices[1]).data_tracked_poly();
    (src_col, ind_col, length_poly)
}

fn payload_verifier<B: SnarkBackend>(
    gadget_ready_ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
) -> (
    arithmetic::col_oracle::TrackedColOracle<B>,
    arithmetic::col_oracle::TrackedColOracle<B>,
    ark_piop::verifier::structs::oracle::TrackedOracle<B>,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
    else {
        panic!("Expected gadget payload for ActivatorConsistencyCheck gadget node");
    };
    let lhs = payload
        .get(LHS_LABEL)
        .expect("ActivatorConsistencyCheck: missing LHS payload");
    let rhs = payload
        .get(RHS_LABEL)
        .expect("ActivatorConsistencyCheck: missing RHS payload");

    let lhs_indices = lhs.data_tracked_oracles_indices();
    assert_eq!(
        lhs_indices.len(),
        1,
        "ActivatorConsistencyCheck LHS must have exactly one data column (src)"
    );
    let rhs_indices = rhs.data_tracked_oracles_indices();
    assert_eq!(
        rhs_indices.len(),
        2,
        "ActivatorConsistencyCheck RHS must have exactly two data columns (ind, l)"
    );

    let src_col_oracle = lhs.tracked_col_oracle_by_ind(lhs_indices[0]);
    let ind_col_oracle = rhs.tracked_col_oracle_by_ind(rhs_indices[0]);
    let length_oracle = rhs
        .tracked_col_oracle_by_ind(rhs_indices[1])
        .data_tracked_oracle();
    (src_col_oracle, ind_col_oracle, length_oracle)
}

#[cfg(test)]
mod tests;
