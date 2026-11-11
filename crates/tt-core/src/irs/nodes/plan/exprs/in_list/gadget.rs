//! Membership gadget for `x [NOT] IN (v1, .., vk)` over literals.
//!
//! The data columns of `x` and of every `vi` are folded with the same
//! challenges into `f` and `gi`, and `P = ∏(f − gi)` is built in Horner form
//! from its public coefficients, so it expands to one term per power of `f`
//! rather than one per subset of the list. With `b` the committed result,
//! `act` the activator (1 without one) and `m` the rows where `x` is in the
//! list (`b`, or `act − b` for `NOT IN`):
//! - `m·P = 0`: a row in `m` folds to some `gi`;
//! - `P + γ·(1 − (act − m))` is nonzero: an active row outside `m` folds to
//!   no `gi`;
//! - `b` is boolean, and 0 on inactive rows.
//!
//! The fold challenges are drawn after `x` and `b` are committed, so a row
//! with `x ≠ vi` folds to `gi` with probability at most `1/|F|` per value.

use std::sync::Arc;

use arithmetic::{encoding::is_rank_segment, is_system_column};
use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    prover::{
        errors::{HonestProverError, ProverError},
        structs::polynomial::TrackedPoly,
    },
    verifier::{errors::VerifierError, structs::oracle::TrackedOracle},
};
use datafusion_common::ScalarValue;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps, utils::bool,
};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub const INPUT_LABEL: &str = "input";
pub const OUTPUT_LABEL: &str = "output";

pub struct InListNode<B: SnarkBackend> {
    /// The row-domain segments of each list value, in the order `x`'s data
    /// columns have them.
    values: Vec<Vec<B::F>>,
    negated: bool,
    bool_check: Arc<Node<B>>,
}

impl<B: SnarkBackend> InListNode<B> {
    pub fn new(list: &[ScalarValue], negated: bool) -> Self {
        assert!(!list.is_empty(), "an IN list needs at least one value");
        let values = list
            .iter()
            .map(|value| {
                arithmetic::encoding::scalar_to_fields::<B::F>(value)
                    .unwrap_or_else(|| panic!("IN list value {value} has no field encoding"))
                    .iter()
                    .map(|segment| segment.value_as_field(0))
                    .collect()
            })
            .collect();
        Self {
            values,
            negated,
            bool_check: Arc::new(Node::<B>::Gadget(Arc::new(bool::GadgetNode::<B>::new()))),
        }
    }

    /// The coefficients of `∏(X − gi)`, constant term first.
    fn vanishing_coefficients(&self, challenges: &[B::F]) -> Vec<B::F> {
        let mut coeffs = vec![B::F::one()];
        for value in &self.values {
            let root: B::F = value.iter().zip(challenges).map(|(v, c)| *v * c).sum();
            let mut next = vec![B::F::zero(); coeffs.len() + 1];
            for (d, coeff) in coeffs.iter().enumerate() {
                next[d + 1] += coeff;
                next[d] -= root * coeff;
            }
            coeffs = next;
        }
        coeffs
    }

    fn segment_count(&self) -> usize {
        self.values[0].len()
    }
}

impl<B: SnarkBackend> IsNode<B> for InListNode<B> {
    fn name(&self) -> String {
        "InList Membership".to_string()
    }

    fn display(&self) -> String {
        let name = format!("{}\nValues: {}", self.name(), self.values.len());
        crate::irs::nodes::display_with_inputs(&name, &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.bool_check.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for InListNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let output = payload
            .get(OUTPUT_LABEL)
            .expect("InList gadget expects its output table")
            .clone();
        virtualized_ir.set_payload_for_node(
            self.bool_check.id(),
            Some(PayloadStructure::GadgetPayload(IndexMap::from([(
                bool::TABLE_LABEL.to_string(),
                output,
            )]))),
        );
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

impl<B: SnarkBackend> VerifierNodeOps<B> for InListNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let output = payload
            .get(OUTPUT_LABEL)
            .expect("InList gadget expects its output table")
            .clone();
        virtualized_ir.set_payload_for_node(
            self.bool_check.id(),
            Some(PayloadStructure::GadgetPayload(IndexMap::from([(
                bool::TABLE_LABEL.to_string(),
                output,
            )]))),
        );
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

impl<B: SnarkBackend> IsGadgetNode<B> for InListNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(input), Some(output)) = (payload.get(INPUT_LABEL), payload.get(OUTPUT_LABEL))
        else {
            panic!("InList gadget expects its input and output tables");
        };
        let columns: Vec<TrackedPoly<B>> = input
            .tracked_polys_iter()
            .filter(|(field, _)| !is_system_column(field.name()) && !is_rank_segment(field.name()))
            .map(|(_, poly)| poly.clone())
            .collect();
        assert_eq!(
            columns.len(),
            self.segment_count(),
            "IN list values and the tested expression encode to different column counts"
        );
        let activator = input.activator_tracked_poly();
        let output_ind = output.data_tracked_polys_indices()[0];
        let b = output.tracked_col_by_ind(output_ind).data_tracked_poly();

        let mut challenges = Vec::with_capacity(columns.len());
        for _ in 0..columns.len() {
            challenges.push(prover.get_and_append_challenge(b"in_list_fold")?);
        }
        let f = columns
            .iter()
            .zip(&challenges)
            .map(|(column, c)| column.mul_scalar_poly(*c))
            .reduce(|acc, term| &acc + &term)
            .expect("the tested expression has a data column");
        let coeffs = self.vanishing_coefficients(&challenges);
        let mut p = f.add_scalar_poly(coeffs[coeffs.len() - 2]);
        for coeff in coeffs[..coeffs.len() - 2].iter().rev() {
            p = (&p * &f).add_scalar_poly(*coeff);
        }

        let one_minus = |poly: &TrackedPoly<B>| {
            poly.mul_scalar_poly(-B::F::one())
                .add_scalar_poly(B::F::one())
        };
        let not_b = match &activator {
            Some(act) => act - &b,
            None => one_minus(&b),
        };
        let (member, non_member) = match self.negated {
            false => (b.clone(), not_b),
            true => (not_b, b.clone()),
        };
        let gamma = prover.get_and_append_challenge(b"in_list")?;
        let nonzero = &p + &one_minus(&non_member).mul_scalar_poly(gamma);
        let mut zero_claims = vec![&member * &p];
        if let Some(act) = &activator {
            zero_claims.push(&act.sub_scalar_poly(B::F::one()) * &b);
        }
        for claim in zero_claims {
            match claim.as_constant() {
                None => prover.add_mv_zerocheck_claim(claim.id())?,
                Some(c) if c.is_zero() => {}
                Some(_) => {
                    return Err(SnarkError::ProverError(ProverError::HonestProverError(
                        HonestProverError::FalseClaim,
                    )));
                }
            }
        }
        match nonzero.as_constant() {
            None => prover.add_mv_nozerocheck_claim(nonzero.id())?,
            Some(c) if !c.is_zero() => {}
            Some(_) => {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(input), Some(output)) = (payload.get(INPUT_LABEL), payload.get(OUTPUT_LABEL))
        else {
            return Ok(());
        };
        let columns: Vec<Vec<B::F>> = input
            .tracked_polys_iter()
            .filter(|(field, _)| !is_system_column(field.name()) && !is_rank_segment(field.name()))
            .map(|(_, poly)| poly.evaluations())
            .collect();
        let activator = input.activator_tracked_poly().map(|act| act.evaluations());
        let output_ind = output.data_tracked_polys_indices()[0];
        let b = output
            .tracked_col_by_ind(output_ind)
            .data_tracked_poly()
            .evaluations();
        for (row, b) in b.iter().enumerate() {
            let expected = match &activator {
                Some(act) if act[row].is_zero() => false,
                _ => {
                    let member = self.values.iter().any(|value| {
                        value
                            .iter()
                            .zip(&columns)
                            .all(|(v, column)| column[row] == *v)
                    });
                    member != self.negated
                }
            };
            if *b != B::F::from(expected) {
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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(input), Some(output)) = (payload.get(INPUT_LABEL), payload.get(OUTPUT_LABEL))
        else {
            panic!("InList gadget expects its input and output tables");
        };
        let columns: Vec<TrackedOracle<B>> = input
            .tracked_oracles_iter()
            .filter(|(field, _)| !is_system_column(field.name()) && !is_rank_segment(field.name()))
            .map(|(_, oracle)| oracle.clone())
            .collect();
        if columns.len() != self.segment_count() {
            return Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed(
                    "IN list values and the tested expression encode to different column counts"
                        .to_string(),
                ),
            ));
        }
        let activator = input.activator_tracked_poly();
        let output_ind = output.data_tracked_oracles_indices()[0];
        let b = output
            .tracked_col_oracle_by_ind(output_ind)
            .data_tracked_oracle();

        let mut challenges = Vec::with_capacity(columns.len());
        for _ in 0..columns.len() {
            challenges.push(verifier.get_and_append_challenge(b"in_list_fold")?);
        }
        let f = columns
            .iter()
            .zip(&challenges)
            .map(|(column, c)| column.mul_scalar_oracle(*c))
            .reduce(|acc, term| &acc + &term)
            .expect("the tested expression has a data column");
        let coeffs = self.vanishing_coefficients(&challenges);
        let mut p = f.add_scalar_oracle(coeffs[coeffs.len() - 2]);
        for coeff in coeffs[..coeffs.len() - 2].iter().rev() {
            p = (&p * &f).add_scalar_oracle(*coeff);
        }

        let one_minus = |oracle: &TrackedOracle<B>| {
            oracle
                .mul_scalar_oracle(-B::F::one())
                .add_scalar_oracle(B::F::one())
        };
        let not_b = match &activator {
            Some(act) => act - &b,
            None => one_minus(&b),
        };
        let (member, non_member) = match self.negated {
            false => (b.clone(), not_b),
            true => (not_b, b.clone()),
        };
        let gamma = verifier.get_and_append_challenge(b"in_list")?;
        let nonzero = &p + &one_minus(&non_member).mul_scalar_oracle(gamma);
        let mut zero_claims = vec![&member * &p];
        if let Some(act) = &activator {
            zero_claims.push(&act.sub_scalar_oracle(B::F::one()) * &b);
        }
        for claim in zero_claims {
            match claim.as_constant() {
                None => verifier.add_mv_zerocheck_claim(claim.id()),
                Some(c) if c.is_zero() => {}
                Some(_) => {
                    return Err(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(
                            "InList: a constant zerocheck is nonzero".to_string(),
                        ),
                    ));
                }
            }
        }
        match nonzero.as_constant() {
            None => verifier.add_mv_nozerocheck_claim(nonzero.id()),
            Some(c) if !c.is_zero() => {}
            Some(_) => {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed(
                        "InList: a constant nonzero check is zero".to_string(),
                    ),
                ));
            }
        }
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}
