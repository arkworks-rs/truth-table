//! Bézout's NoDupcheck (paper PIOP 24, Appendix B.1). Only tests select it;
//! production proves NoDup by sorting.
//!
//! With `c` the input folded into one column and `a` its activator, the
//! leaves `a·(Y − c) + (1 − a)` multiply to `z(Y) = ∏_{a = 1} (Y − c)`. The
//! active entries of `c` are distinct iff `z` has no repeated root, iff
//! `t·z + s·z' = 1` for some `t`, `s`.
//! 1. P commits the univariate `t` and `s`; V then samples `r`. Sending them
//!    after `r` would let P answer with `t = 1/z(r)`, `s = 0`.
//! 2. P commits the running product `P[i] = ∏_{j ≤ i} L_j` of the leaves
//!    `L = a·(r − c) + (1 − a)`, its derivative `Q[i]` in `Y`, and both
//!    rotated down by one row. A rotation check binds the rotated copies,
//!    and two zerochecks the recurrences, with `P↑`, `Q↑` the previous row's
//!    values (`1` and `0` on row 0):
//!    `P = L·P↑` and `Q = L·Q↑ + a·P↑`.
//! 3. V checks `t(r)·P(1, …, 1) + s(r)·Q(1, …, 1) = 1`.
//!
//! The running products stand in for the paper's product trees (Eqs. 3, 4),
//! whose zerochecks read `f` with shifted variables. An inactive leaf is `1`
//! with derivative `0`, so inactive rows need no random padding.

use std::sync::{Arc, Mutex};

use super::{GadgetNode, INPUT_LABEL};
use crate::irs::nodes::{Node, utils::rotation_check};
use crate::irs::payloads::PayloadStructure;
use crate::irs::{ir::Ir, tree::Payload};
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{FftField, One, PrimeField, Zero};
use ark_piop::arithmetic::mat_poly::lde::LDE;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    types::TrackerID,
    verifier::{ArgVerifier, errors::VerifierError, structs::oracle::TrackedOracle},
};
use ark_poly::DenseUVPolynomial;
use ark_poly::Polynomial;
use ark_poly::univariate::DenseOrSparsePolynomial;
use ark_std::cfg_iter;
use datafusion::arrow::datatypes::{DataType, Field as ArrowField, FieldRef, Schema};
use indexmap::IndexMap;
#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

pub struct BezoutGadgets<B: SnarkBackend> {
    /// Binds `P↑`, `Q↑` to `P`, `Q`.
    pub(super) rotation: Arc<Node<B>>,
    /// Set by the verifier's `initialize_gadgets` for the check of step 3.
    identity: Mutex<Option<IdentityQuery<B::F>>>,
}

struct IdentityQuery<F> {
    product: TrackerID,
    derivative: TrackerID,
    t: TrackerID,
    s: TrackerID,
    r: F,
    log_size: usize,
}

impl<B: SnarkBackend> BezoutGadgets<B> {
    pub(super) fn new() -> Self {
        Self {
            rotation: Arc::new(Node::Gadget(Arc::new(rotation_check::GadgetNode::new(
                1,
                rotation_check::Direction::Right,
            )))),
            identity: Mutex::new(None),
        }
    }

    /// Step 3: `t(r)·P(1, …, 1) + s(r)·Q(1, …, 1) = 1`.
    pub(super) fn check_identity(&self, verifier: &mut ArgVerifier<B>) -> SnarkResult<()> {
        let query = self
            .identity
            .lock()
            .expect("Bezout identity lock should not be poisoned")
            .take()
            .expect("the verifier's initialize_gadgets sets the Bezout query");
        let last_row = vec![B::F::one(); query.log_size];
        let z_at_r = verifier.query_mv(query.product, last_row.clone())?;
        let z_prime_at_r = verifier.query_mv(query.derivative, last_row)?;
        let t_at_r = verifier.query_uv(query.t, query.r)?;
        let s_at_r = verifier.query_uv(query.s, query.r)?;
        if !(t_at_r * z_at_r + s_at_r * z_prime_at_r).is_one() {
            return Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed("Bezout identity check failed".to_string()),
            ));
        }
        Ok(())
    }
}

thread_local! {
    /// Makes the prover set the last running product to the value that
    /// passes the Bézout identity, as a prover with duplicates would.
    pub(super) static FORGE_PRODUCT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn running_fields() -> [FieldRef; 2] {
    ["product", "derivative"].map(|name| Arc::new(ArrowField::new(name, DataType::UInt64, false)))
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub(super) fn prove_nodup_bezout(
        prover: &mut ArgProver<B>,
        ir: &mut crate::prover::irs::VirtualizedIr<B>,
        id: crate::irs::nodes::NodeId,
        gadgets: &BezoutGadgets<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
            panic!("Expected gadget payload for NoDup gadget node");
        };
        let Some(input_table) = payload.get(INPUT_LABEL).cloned() else {
            panic!("Expected input table for NoDup gadget");
        };
        let col = Self::single_col_from_table(prover, &input_table)?;
        let c = col.data_tracked_poly();
        let a = col.activator_tracked_poly();
        let log_size = c.log_size();
        let c_evals = c.evaluations();
        let a_evals = a.as_ref().map(|a| a.evaluations());
        let a_at = |i: usize| a_evals.as_ref().map_or(B::F::one(), |a| a[i]);

        let roots: Vec<B::F> = (0..c_evals.len())
            .filter(|&i| a_at(i).is_one())
            .map(|i| c_evals[i])
            .collect();
        let z = build_root_products(&roots);
        let (t, s) = bez_polys(&z, &d_dx(&z));
        let t = prover.track_and_commit_mat_uv_poly(t)?;
        let s = prover.track_and_commit_mat_uv_poly(s)?;

        let r: B::F = prover.get_and_append_challenge(b"bezout")?;

        let mut product = Vec::with_capacity(c_evals.len());
        let mut derivative = Vec::with_capacity(c_evals.len());
        let (mut p_up, mut q_up) = (B::F::one(), B::F::zero());
        for (i, c_i) in c_evals.iter().enumerate() {
            let a_i = a_at(i);
            let leaf = a_i * (r - c_i) + B::F::one() - a_i;
            q_up = q_up * leaf + p_up * a_i;
            p_up *= leaf;
            product.push(p_up);
            derivative.push(q_up);
        }
        #[cfg(test)]
        if FORGE_PRODUCT.get() {
            // The value of `z(r)` that makes the identity of step 3 hold.
            let last = product.len() - 1;
            let t_at_r = t.evaluate_uv(&r).expect("t is univariate");
            let s_at_r = s.evaluate_uv(&r).expect("s is univariate");
            product[last] = (B::F::one() - s_at_r * derivative[last]) / t_at_r;
        }
        let mut commit = |evals: Vec<B::F>| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, evals))
        };
        let p = commit(product.clone())?;
        let q = commit(derivative.clone())?;
        let p_prev = commit(rotated_down(&product))?;
        let q_prev = commit(rotated_down(&derivative))?;

        let first = prover.get_or_build_contig_one_poly(log_size, 1)?;
        let not_first = first
            .mul_scalar_poly(-B::F::one())
            .add_scalar_poly(B::F::one());
        let p_up = &(&p_prev * &not_first) + &first;
        let q_up = &q_prev * &not_first;
        let (leaf, leaf_derivative_times_p_up) = match &a {
            Some(a) => (
                (a * &c
                    .mul_scalar_poly(-B::F::one())
                    .add_scalar_poly(r - B::F::one()))
                    .add_scalar_poly(B::F::one()),
                a * &p_up,
            ),
            None => (
                c.mul_scalar_poly(-B::F::one()).add_scalar_poly(r),
                p_up.clone(),
            ),
        };
        prover.add_mv_zerocheck_claim((&p - &(&leaf * &p_up)).id())?;
        prover.add_mv_zerocheck_claim(
            (&(&q - &(&leaf * &q_up)) - &leaf_derivative_times_p_up).id(),
        )?;

        let last_row = vec![B::F::one(); log_size];
        prover.add_mv_eval_claim(p.id(), &last_row)?;
        prover.add_mv_eval_claim(q.id(), &last_row)?;
        prover.add_uv_eval_claim(t.id(), r)?;
        prover.add_uv_eval_claim(s.id(), r)?;

        let table = |polys: [TrackedPoly<B>; 2]| {
            TrackedTable::new(
                Some(running_schema()),
                running_fields()
                    .into_iter()
                    .zip(polys)
                    .collect::<IndexMap<_, _>>(),
                log_size,
            )
        };
        set_rotation_payload(
            ir,
            &gadgets.rotation,
            table([p, q]),
            table([p_prev, q_prev]),
        );
        Ok(())
    }

    pub(super) fn verify_nodup_bezout(
        verifier: &mut ArgVerifier<B>,
        ir: &mut crate::verifier::irs::VirtualizedIr<B>,
        id: crate::irs::nodes::NodeId,
        gadgets: &BezoutGadgets<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
            panic!("Expected gadget payload for NoDup gadget node");
        };
        let Some(input_table) = payload.get(INPUT_LABEL).cloned() else {
            panic!("Expected input table for NoDup gadget");
        };
        let col = Self::single_col_from_table_oracle(verifier, &input_table)?;
        let c = col.data_tracked_oracle();
        let a = col.activator_tracked_oracle();
        let log_size = c.log_size();

        let t = verifier.track_next_uv_com()?;
        let s = verifier.track_next_uv_com()?;

        let r: B::F = verifier.get_and_append_challenge(b"bezout")?;

        let p = verifier.track_next_mv_com()?;
        let q = verifier.track_next_mv_com()?;
        let p_prev = verifier.track_next_mv_com()?;
        let q_prev = verifier.track_next_mv_com()?;

        let first = verifier.get_or_build_contig_one_poly(log_size, 1)?;
        let not_first = first
            .mul_scalar_oracle(-B::F::one())
            .add_scalar_oracle(B::F::one());
        let p_up = &(&p_prev * &not_first) + &first;
        let q_up = &q_prev * &not_first;
        let (leaf, leaf_derivative_times_p_up) = match &a {
            Some(a) => (
                (a * &c
                    .mul_scalar_oracle(-B::F::one())
                    .add_scalar_oracle(r - B::F::one()))
                    .add_scalar_oracle(B::F::one()),
                a * &p_up,
            ),
            None => (
                c.mul_scalar_oracle(-B::F::one()).add_scalar_oracle(r),
                p_up.clone(),
            ),
        };
        verifier.add_mv_zerocheck_claim((&p - &(&leaf * &p_up)).id());
        verifier
            .add_mv_zerocheck_claim((&(&q - &(&leaf * &q_up)) - &leaf_derivative_times_p_up).id());

        *gadgets
            .identity
            .lock()
            .expect("Bezout identity lock should not be poisoned") = Some(IdentityQuery {
            product: p.id(),
            derivative: q.id(),
            t: t.id(),
            s: s.id(),
            r,
            log_size,
        });

        let table = |oracles: [TrackedOracle<B>; 2]| {
            TrackedTableOracle::new(
                Some(running_schema()),
                running_fields()
                    .into_iter()
                    .zip(oracles)
                    .collect::<IndexMap<_, _>>(),
                log_size,
            )
        };
        set_rotation_payload(
            ir,
            &gadgets.rotation,
            table([p, q]),
            table([p_prev, q_prev]),
        );
        Ok(())
    }

    fn single_col_from_table(
        prover: &mut ArgProver<B>,
        table: &TrackedTable<B>,
    ) -> ark_piop::errors::SnarkResult<TrackedCol<B>> {
        let data_indices = table.data_tracked_polys_indices();
        if data_indices.len() == 1 {
            return Ok(table.tracked_col_by_ind(data_indices[0]));
        }
        let mut challenges = Vec::with_capacity(data_indices.len());
        for _ in 0..data_indices.len() {
            challenges.push(prover.get_and_append_challenge(b"nodup_fold")?);
        }
        Ok(table.fold_all_data_columns(&challenges))
    }

    fn single_col_from_table_oracle(
        verifier: &mut ArgVerifier<B>,
        table: &TrackedTableOracle<B>,
    ) -> ark_piop::errors::SnarkResult<TrackedColOracle<B>> {
        let data_indices = table.data_tracked_oracles_indices();
        if data_indices.len() == 1 {
            return Ok(table.tracked_col_oracle_by_ind(data_indices[0]));
        }
        let mut challenges = Vec::with_capacity(data_indices.len());
        for _ in 0..data_indices.len() {
            challenges.push(verifier.get_and_append_challenge(b"nodup_fold")?);
        }
        Ok(table.fold_all_data_oracles(&challenges))
    }
}

/// `values` moved down one row, the last value wrapping to row 0.
fn rotated_down<F: Copy>(values: &[F]) -> Vec<F> {
    let mut rotated = Vec::with_capacity(values.len());
    rotated.extend(values.last().copied());
    rotated.extend_from_slice(&values[..values.len().saturating_sub(1)]);
    rotated
}

fn running_schema() -> Schema {
    Schema::new(
        running_fields()
            .into_iter()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    )
}

fn set_rotation_payload<B: SnarkBackend, T: Clone>(
    ir: &mut Ir<B, PayloadStructure<T>>,
    rotation: &Arc<Node<B>>,
    left: T,
    right: T,
) where
    PayloadStructure<T>: Payload,
{
    let mut payload = match ir.payload_for_node(&rotation.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    payload.insert(rotation_check::LEFT_LABEL.to_string(), left);
    payload.insert(rotation_check::RIGHT_LABEL.to_string(), right);
    ir.set_payload_for_node(
        rotation.id(),
        Some(PayloadStructure::GadgetPayload(payload)),
    );
}

/// The polynomial `∏ (Y − root)` over `roots`.
pub fn build_root_products<F: FftField>(roots: &[F]) -> LDE<F> {
    match roots {
        [] => LDE::from_coefficients_vec(vec![F::one()]),
        [root] => LDE::from_coefficients_vec(vec![-*root, F::one()]),
        _ => {
            let (left, right) = roots.split_at(roots.len() / 2);
            let (left, right) =
                rayon::join(|| build_root_products(left), || build_root_products(right));
            left * right
        }
    }
}

pub fn d_dx<F: PrimeField>(poly: &LDE<F>) -> LDE<F> {
    let coeffs: Vec<F> = cfg_iter!(poly.coeffs)
        .enumerate()
        .skip(1) // the derivative of the constant term is 0
        .map(|(i, coeff)| F::from(i as u64) * coeff)
        .collect();

    LDE { coeffs }
}

/// Classical extended GCD, used for small-degree polynomials.
fn classical_xgcd_polynomials_par<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    if b.is_zero() {
        let gcd_val = a.coeffs[0];
        let gcd_inv = gcd_val.inverse().unwrap();
        return (LDE::from_coefficients_vec(vec![gcd_inv]), LDE::zero());
    }

    let a_dsp = DenseOrSparsePolynomial::from(a);
    let b_dsp = DenseOrSparsePolynomial::from(b);
    let (q, r) = a_dsp.divide_with_q_and_r(&b_dsp).unwrap();

    let (f_sub, g_sub) = classical_xgcd_polynomials_par(b, &r);

    let qg = q * (&g_sub);
    let next_g = f_sub - (&qg);
    (g_sub, next_g)
}

#[derive(Clone, Debug)]
struct PolyMatrix2x2<F: FftField> {
    a11: LDE<F>,
    a12: LDE<F>,
    a21: LDE<F>,
    a22: LDE<F>,
}

impl<F: FftField> PolyMatrix2x2<F> {
    fn identity() -> Self {
        Self {
            a11: LDE::from_coefficients_vec(vec![F::one()]),
            a12: LDE::zero(),
            a21: LDE::zero(),
            a22: LDE::from_coefficients_vec(vec![F::one()]),
        }
    }

    fn par_multiply(&self, rhs: &Self) -> Self {
        // One task per row; each polynomial product may itself run in parallel.
        let (res_top, res_bot) = rayon::join(
            || {
                let a11 = (&self.a11) * (&rhs.a11) + (&self.a12 * (&rhs.a21));
                let a12 = (&self.a11) * (&rhs.a12) + (&self.a12 * (&rhs.a22));
                (a11, a12)
            },
            || {
                let a21 = (&self.a21) * (&rhs.a11) + (&self.a22 * (&rhs.a21));
                let a22 = (&self.a21) * (&rhs.a12) + (&self.a22 * (&rhs.a22));
                (a21, a22)
            },
        );

        let (a11, a12) = res_top;
        let (a21, a22) = res_bot;
        Self { a11, a12, a21, a22 }
    }

    /// The matrix applied to the column vector `(f, g)`.
    fn par_apply(&self, f: &LDE<F>, g: &LDE<F>) -> (LDE<F>, LDE<F>) {
        let (out1, out2) = rayon::join(
            || (&self.a11) * (f) + (&self.a12 * (g)),
            || (&self.a21) * (f) + (&self.a22 * (g)),
        );
        (out1, out2)
    }
}

/// Euclidean divisions until `deg(r1)` is at most half of `deg(a)`. Returns
/// the product of the step matrices and the last two remainders.
fn partial_gcd_step_par<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (PolyMatrix2x2<F>, LDE<F>, LDE<F>) {
    let mut r0 = a.clone();
    let mut r1 = b.clone();

    let mut m = PolyMatrix2x2::identity();

    let deg_a = r0.degree();
    let half_deg = deg_a / 2;

    while !r1.is_zero() && r1.degree() > half_deg {
        let r0_dsp = DenseOrSparsePolynomial::from(&r0);
        let r1_dsp = DenseOrSparsePolynomial::from(&r1);
        let (q, remainder) = r0_dsp.divide_with_q_and_r(&r1_dsp).unwrap();

        // Matrix for step: (r0, r1) -> (r1, r0 - q*r1)
        //   [0,   1]
        //   [1,  -q]
        let mut minus_q = q.clone();
        minus_q.coeffs.iter_mut().for_each(|c| *c = -(*c));

        let step_mat = PolyMatrix2x2 {
            a11: LDE::zero(),
            a12: LDE::from_coefficients_vec(vec![F::one()]),
            a21: LDE::from_coefficients_vec(vec![F::one()]),
            a22: minus_q,
        };

        m = m.par_multiply(&step_mat);

        r0 = r1;
        r1 = remainder;
    }

    (m, r0, r1)
}

fn half_gcd_polynomials_par<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    if b.is_zero() {
        let gcd_val = a.coeffs[0];
        let gcd_inv = gcd_val.inverse().unwrap();
        return (LDE::from_coefficients_vec(vec![gcd_inv]), LDE::zero());
    }

    // Ensure deg(a) >= deg(b)
    if b.degree() > a.degree() {
        let (f_sub, g_sub) = half_gcd_polynomials_par(b, a);
        return (g_sub, f_sub);
    }

    // Fall back to the classical algorithm on small degrees.
    let threshold = 16;
    if a.degree() <= threshold || b.degree() <= threshold {
        return classical_xgcd_polynomials_par(a, b);
    }

    let (m, r0, r1) = partial_gcd_step_par(a, b);
    let (f_sub, g_sub) = half_gcd_polynomials_par(&r0, &r1);

    // Lift the coefficients of the smaller pair back through the step matrix.
    let (f_res, g_res) = m.par_apply(&f_sub, &g_sub);
    (f_res, g_res)
}

/// Bezout coefficients `(f, g)` with `f * a + g * b = 1`, for coprime `a`
/// and `b`.
pub fn bez_polys<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    half_gcd_polynomials_par(a, b)
}
