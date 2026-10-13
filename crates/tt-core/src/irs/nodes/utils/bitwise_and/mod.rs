//! Bitwise AND check (paper §6.3, PIOP 9).
//!
//! Takes one payload table with three data columns `(c1, c2, c3)` of
//! `n`-bit values and proves `c3[i] = c1[i] ∧ c2[i]` on every active row:
//!
//! 1. Range: each column is looked up in the transparent `n`-bit range
//!    table. The AND lookup below already forces this (every row of its
//!    table is `n`-bit), so these checks follow the paper but soundness
//!    does not rest on them.
//! 2. Fold: the verifier samples `r1, r2, r3` after the columns are
//!    committed, and both parties form `c' = r1·c1 + r2·c2 + r3·c3`.
//! 3. Lookup: the activated `c'` is looked up in the transparent
//!    2n-variable column `c'' = r1·I'ₙ + r2·I''ₙ + r3·ãnd`, whose `2^{2n}`
//!    rows enumerate every triple `(a, b, a ∧ b)`.
//!
//! Soundness: the columns are committed before the challenges, so a row
//! whose triple is not in the AND table collides with a table entry only
//! through a nontrivial linear identity in `r1, r2, r3`: probability at
//! most `rows · 2^{2n} / |F|` in total. Inactive rows fold to `0` through
//! the activator and land on the `(0, 0, 0)` table row.
//!
//! The table needs no oracle: the verifier evaluates the multilinear
//! `I'ₙ(x) = Σ 2^i x_i`, `I''ₙ(x) = Σ 2^i x_{n+i}` and
//! `ãnd(x) = Σ 2^i x_i x_{n+i}` itself, as the Sign gadget does for its
//! range tables. Variable `i` carries bit weight `2^i` (LSB first), the
//! tracker's index-to-variable convention.

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    prover::ArgProver,
    verifier::{ArgVerifier, structs::oracle::Oracle},
};
use indexmap::IndexMap;
use std::marker::PhantomData;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const INPUT_LABEL: &str = "__input__";

/// With [`GadgetNode::new_with_constant`], `c2` is a public constant `φ`
/// (the paper's `φ·1`) instead of a payload column: the payload carries
/// only `(c1, c3)` and the constant adds the scalar `r2·φ` to the folded
/// column, with no oracle. The lookup table is unchanged, so active rows
/// are forced onto AND-table triples whose middle slot is `φ`.
pub struct GadgetNode<B: SnarkBackend> {
    bit_width: usize,
    constant_operand: Option<u64>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    /// `bit_width` is the paper's `n`. The transparent AND table has
    /// `2^{2·bit_width}` rows, so keep the width small (fingerprint bin
    /// counts, not machine words).
    pub fn new(bit_width: usize) -> Self {
        assert!(bit_width > 0, "BitwiseAnd requires a positive bit width");
        Self {
            bit_width,
            constant_operand: None,
            _phantom: PhantomData,
        }
    }

    /// Constant mode: proves `c3 = c1 ∧ constant` for a public
    /// `bit_width`-bit `constant`.
    pub fn new_with_constant(bit_width: usize, constant: u64) -> Self {
        assert!(bit_width > 0, "BitwiseAnd requires a positive bit width");
        assert!(
            bit_width >= 64 || constant < (1u64 << bit_width),
            "BitwiseAnd constant operand must be a bit_width-bit value"
        );
        Self {
            bit_width,
            constant_operand: Some(constant),
            _phantom: PhantomData,
        }
    }

    pub fn bit_width(&self) -> usize {
        self.bit_width
    }

    /// Shared label so range tables dedupe with the Sign gadget's.
    fn range_poly_label(nv: usize) -> String {
        format!("range_{}", nv)
    }

    /// Prover-side transparent range table: `evals[x] = x` over `nv` vars.
    fn dense_range_poly(nv: usize) -> MLE<B::F> {
        let evals = (0..1usize << nv)
            .map(|x| B::F::from(x as u64))
            .collect::<Vec<_>>();
        MLE::from_evaluations_vec(nv, evals)
    }

    /// Register `col ⊑ range_{nv}` on the prover side (activated data, so
    /// inactive rows fold to `0`, which the table contains).
    fn add_range_inclusion(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
        nv: usize,
    ) -> SnarkResult<()> {
        let col_activated_poly = col.activated_data_tracked_poly();
        let label = Self::range_poly_label(nv);
        let range_poly = match prover.indexed_tracked_poly(label.clone()) {
            Ok(poly) => poly,
            Err(_) => {
                let poly = prover.track_mat_mv_poly(Self::dense_range_poly(nv));
                prover.add_indexed_tracked_poly(label, poly.clone());
                poly
            }
        };
        prover.add_mv_lookup_claim(range_poly.id(), col_activated_poly.id())
    }

    /// Verifier-side transparent range oracle: `Σ 2^i x_i` over `nv` vars.
    fn range_oracle(nv: usize) -> Oracle<B::F> {
        Oracle::new_multivariate(nv, move |x: Vec<B::F>| {
            let mut acc = B::F::zero();
            let mut w = B::F::one();
            let two = B::F::from(2u64);
            for xi in x.iter().take(nv) {
                acc += w * xi;
                w *= two;
            }
            Ok(acc)
        })
    }

    fn add_range_inclusion_oracle(
        verifier: &mut ArgVerifier<B>,
        col: &TrackedColOracle<B>,
        nv: usize,
    ) -> SnarkResult<()> {
        let col_activated_oracle = col.activated_data_tracked_oracle();
        let label = Self::range_poly_label(nv);
        let range_oracle = match verifier.indexed_tracked_poly(label.clone()) {
            Ok(oracle) => oracle,
            Err(_) => {
                let oracle = verifier.track_base_oracle(Self::range_oracle(nv));
                verifier.add_indexed_tracked_poly(label, oracle.clone());
                oracle
            }
        };
        verifier.add_mv_lookup_claim(range_oracle.id(), col_activated_oracle.id())
    }

    /// Prover-side transparent AND table: `2n` variables, row `idx`
    /// holding `r1·a + r2·b + r3·(a ∧ b)` with `a` the low and `b` the
    /// high `n` bits of `idx`. Challenge-dependent, so never dedup-cached.
    pub(crate) fn dense_and_table(bit_width: usize, rs: &[B::F; 3]) -> MLE<B::F> {
        let mask = (1u64 << bit_width) - 1;
        let evals = (0..1usize << (2 * bit_width))
            .map(|idx| {
                let a = idx as u64 & mask;
                let b = (idx as u64 >> bit_width) & mask;
                rs[0] * B::F::from(a) + rs[1] * B::F::from(b) + rs[2] * B::F::from(a & b)
            })
            .collect::<Vec<_>>();
        MLE::from_evaluations_vec(2 * bit_width, evals)
    }

    /// Verifier-side transparent AND table oracle:
    /// `r1·Σ2^i x_i + r2·Σ2^i x_{n+i} + r3·Σ2^i x_i·x_{n+i}`, the
    /// multilinear extension of [`Self::dense_and_table`].
    pub(crate) fn and_table_oracle(bit_width: usize, rs: [B::F; 3]) -> Oracle<B::F> {
        Oracle::new_multivariate(2 * bit_width, move |x: Vec<B::F>| {
            let mut acc = B::F::zero();
            let mut w = B::F::one();
            let two = B::F::from(2u64);
            for i in 0..bit_width {
                acc +=
                    w * (rs[0] * x[i] + rs[1] * x[bit_width + i] + rs[2] * x[i] * x[bit_width + i]);
                w *= two;
            }
            Ok(acc)
        })
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "BitwiseAnd".to_string()
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
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for BitwiseAnd gadget node");
        };
        let Some(input) = payload.get(INPUT_LABEL) else {
            panic!("Expected input table for BitwiseAnd gadget");
        };
        let data_inds = input.data_tracked_polys_indices();
        let expected_cols = if self.constant_operand.is_some() {
            2
        } else {
            3
        };
        assert_eq!(
            data_inds.len(),
            expected_cols,
            "BitwiseAnd expects (c1, c2, c3) data columns, or (c1, c3) in constant mode."
        );

        // The constant operand, if any, is public and its range is asserted
        // at construction.
        for &ind in &data_inds {
            let col = input.tracked_col_by_ind(ind);
            Self::add_range_inclusion(prover, &col, self.bit_width)?;
        }

        // Drawn after the columns are committed.
        let rs = [
            prover.get_and_append_challenge(b"bitwise_and_fold")?,
            prover.get_and_append_challenge(b"bitwise_and_fold")?,
            prover.get_and_append_challenge(b"bitwise_and_fold")?,
        ];

        // Activation multiplies the whole combined value, constant term
        // included, so inactive rows land on the (0, 0, 0) table row.
        let combined_activated = match self.constant_operand {
            None => input.fold(&data_inds, &rs).activated_data_tracked_poly(),
            Some(constant) => {
                let folded = input.fold(&data_inds, &[rs[0], rs[2]]);
                let with_const = folded
                    .data_tracked_poly()
                    .add_scalar_poly(rs[1] * B::F::from(constant));
                match folded.activator_tracked_poly() {
                    Some(act) => &with_const * &act,
                    None => with_const,
                }
            }
        };
        let and_table = prover.track_mat_mv_poly(Self::dense_and_table(self.bit_width, &rs));
        prover.add_mv_lookup_claim(and_table.id(), combined_activated.id())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for BitwiseAnd gadget node");
        };
        let Some(input) = payload.get(INPUT_LABEL) else {
            panic!("Expected input table for BitwiseAnd gadget");
        };
        let data_inds = input.data_tracked_oracles_indices();
        let expected_cols = if self.constant_operand.is_some() {
            2
        } else {
            3
        };
        assert_eq!(
            data_inds.len(),
            expected_cols,
            "BitwiseAnd expects (c1, c2, c3) data columns, or (c1, c3) in constant mode."
        );

        for &ind in &data_inds {
            let col = input.tracked_col_oracle_by_ind(ind);
            Self::add_range_inclusion_oracle(verifier, &col, self.bit_width)?;
        }

        let rs = [
            verifier.get_and_append_challenge(b"bitwise_and_fold")?,
            verifier.get_and_append_challenge(b"bitwise_and_fold")?,
            verifier.get_and_append_challenge(b"bitwise_and_fold")?,
        ];

        let combined_activated = match self.constant_operand {
            None => input.fold(&data_inds, &rs).activated_data_tracked_oracle(),
            Some(constant) => {
                let folded = input.fold(&data_inds, &[rs[0], rs[2]]);
                let with_const = folded
                    .data_tracked_oracle()
                    .add_scalar_oracle(rs[1] * B::F::from(constant));
                match folded.activator_tracked_oracle() {
                    Some(act) => &with_const * &act,
                    None => with_const,
                }
            }
        };
        let and_table = verifier.track_base_oracle(Self::and_table_oracle(self.bit_width, rs));
        verifier.add_mv_lookup_claim(and_table.id(), combined_activated.id())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

#[cfg(test)]
mod tests;
