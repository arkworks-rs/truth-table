//! Bitwise AND check gadget (paper §6.3, PIOP 9).
//!
//! Takes one payload table with three data columns `(c1, c2, c3)` of
//! `n`-bit values and proves that on every active row `c3[i] = c1[i] ∧
//! c2[i]` (bitwise AND). The protocol:
//!
//! 1. (*Range*) each column is looked up in the transparent `n`-bit range
//!    table, so all entries are `n`-bit. (The AND lookup below already
//!    forces this — every truth-table row is `n`-bit — so these checks
//!    are defense-in-depth per the paper, not load-bearing for
//!    soundness.)
//! 2. (*Fold*) the verifier samples `r1, r2, r3` (after the columns are
//!    committed) and both parties form `c' = r1·c1 + r2·c2 + r3·c3`.
//! 3. (*Lookup*) `c'` (activated) is looked up in the transparent
//!    2n-variable column `c'' = r1·I'ₙ + r2·I''ₙ + r3·ãnd`, whose
//!    2^{2n} rows enumerate every valid triple `(a, b, a ∧ b)`.
//!
//! Soundness: the columns are committed before `r1, r2, r3` are sampled,
//! so for a row whose triple is *not* an AND-table row, colliding with
//! any table entry is a nontrivial linear identity in the challenges —
//! probability ≤ `rows · 2^{2n} / |F|` in total. Inactive rows fold to
//! `0` via the activator and land on the `(0, 0, 0)` table row.
//!
//! The table columns need no oracle: the verifier evaluates
//! `I'ₙ(x) = Σ 2^i x_i`, `I''ₙ(x) = Σ 2^i x_{n+i}` and
//! `ãnd(x) = Σ 2^i x_i x_{n+i}` (all multilinear) by itself, mirroring
//! the transparent range tables of the Sign gadget. Variable `i` carries
//! bit weight `2^i` (LSB-first), matching the tracker's index ↔ variable
//! convention.

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

/// Label for the single payload table carrying the `(c1, c2, c3)` data
/// columns (and their shared activator, if any).
pub const INPUT_LABEL: &str = "__input__";

/// A gadget node proving `c3 = c1 ∧ c2` bitwise over `bit_width`-bit
/// values, on all activated rows.
///
/// With [`GadgetNode::new_with_constant`], `c2` is a public constant `φ`
/// instead of a payload column (the paper's `φ·1`): the payload then
/// carries only `(c1, c3)`, and the constant contributes the scalar
/// `r2·φ` to the folded column — no oracle, no commitment, matching the
/// paper's "the constant column needs no oracle" remark. The lookup
/// table is unchanged, so active rows are forced onto AND-table triples
/// whose middle slot is exactly `φ`.
pub struct GadgetNode<B: SnarkBackend> {
    bit_width: usize,
    /// `Some(φ)`: prove `c3 = c1 ∧ φ` against a public constant second
    /// operand; the payload carries two data columns `(c1, c3)`.
    constant_operand: Option<u64>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    /// `bit_width` is the paper's `n`: the number of bits per value. The
    /// transparent AND table has `2^{2·bit_width}` rows, so keep the
    /// width small (fingerprint bin counts, not machine words).
    pub fn new(bit_width: usize) -> Self {
        assert!(bit_width > 0, "BitwiseAnd requires a positive bit width");
        Self {
            bit_width,
            constant_operand: None,
            _phantom: PhantomData,
        }
    }

    /// Prove `c3 = c1 ∧ constant` with a public `bit_width`-bit constant
    /// second operand (no oracle needed for it).
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
    /// `r1·Σ2^i x_i + r2·Σ2^i x_{n+i} + r3·Σ2^i x_i·x_{n+i}` — the
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

        // 1. Range checks: every entry of every column is `bit_width`-bit.
        //    (The constant operand, if any, is public and asserted at
        //    construction.)
        for &ind in &data_inds {
            let col = input.tracked_col_by_ind(ind);
            Self::add_range_inclusion(prover, &col, self.bit_width)?;
        }

        // 2. Fold challenges — drawn after the columns are committed.
        let rs = [
            prover.get_and_append_challenge(b"bitwise_and_fold")?,
            prover.get_and_append_challenge(b"bitwise_and_fold")?,
            prover.get_and_append_challenge(b"bitwise_and_fold")?,
        ];

        // 3. Lookup of the folded (activated) column in the AND table.
        //    Activation multiplies the whole combined value (constant term
        //    included), so inactive rows land on the (0, 0, 0) table row.
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
