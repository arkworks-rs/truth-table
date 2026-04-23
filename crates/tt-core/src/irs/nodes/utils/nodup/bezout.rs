use super::GadgetNode;
use crate::irs::nodes::ProverGadgetReadyIr;
use crate::irs::nodes::utils::nodup::defragg::Defragmenter;
use crate::irs::payloads::PayloadStructure;
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::One;
use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_ff::{FftField, PrimeField};
use ark_piop::arithmetic::index;
use ark_piop::arithmetic::mat_poly::lde::LDE;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, errors::VerifierError},
};
use ark_poly::DenseUVPolynomial;
use ark_poly::Polynomial;
use ark_poly::univariate::DenseOrSparsePolynomial;
use ark_std::cfg_iter;
use ark_std::rand::RngCore;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

impl<B: SnarkBackend> GadgetNode<B> {
    pub(super) fn prove_nodup_bezout(
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut ProverGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for NoDup gadget node");
        };

        let Some(input_table) = payload.get(super::INPUT_LABEL).cloned() else {
            panic!("Expected input table for NoDup gadget");
        };
        let col = Self::single_col_from_table(prover, &input_table)?;
        ///////////////////// Deduplication check /////////////////////
        let defraged_in_col = Defragmenter::defrag_col(prover, &col)?;
        ///////////////////// Some useful variables /////////////////////
        // The number of variables in all the polynomials in this protocol
        let num_vars = defraged_in_col.data_tracked_poly().log_size();

        // The final query point for the polynomial f and f', i.e. (1,1,...,1,0)
        let f_query_point: Vec<B::F> = if num_vars == 0 {
            Vec::new()
        } else {
            std::iter::once(B::F::zero())
                .chain((0..num_vars - 1).map(|_| B::F::one()))
                .collect()
        };

        ///////////////////// Compute the deduplicated polynomial /////////////////////
        // TODO: Make sure the randomness is provided safely

        let dedup_mle =
            if let Some(activator_tracked_poly) = defraged_in_col.activator_tracked_poly() {
                let mut rng = ark_std::test_rng();
                let dedup_mle: MLE<B::F> = p_prep(&mut rng, &defraged_in_col)?;
                let dedup_tr_p: TrackedPoly<B> = prover.track_and_commit_mat_mv_poly(&dedup_mle)?;
                let dedup_wit_tr_p: TrackedPoly<B> =
                    &(&dedup_tr_p - &defraged_in_col.data_tracked_poly()) * &activator_tracked_poly;
                prover.add_mv_zerocheck_claim(dedup_wit_tr_p.id())?;
                dedup_mle
            } else {
                MLE::from_evaluations_vec(
                    defraged_in_col.log_size(),
                    defraged_in_col.data_tracked_poly().evaluations(),
                )
            };

        ///////////// Compute the challenge /////////////////////
        let chall: B::F = prover.get_and_append_challenge(b"bezout")?;

        ///////////////////// Compute f, gives us z(r) /////////////////////
        // TODO: Pass around iterators instead of slices
        let chall_minus_ci_evals: Vec<B::F> = dedup_mle
            .evaluations()
            .iter()
            .map(|ci| chall - ci)
            .collect();

        let f_poly = compute_product_poly(&chall_minus_ci_evals, dedup_mle.num_vars())?;
        let f_p_tr = prover.track_and_commit_mat_mv_poly(&f_poly)?;
        ///////////////////// Compute the derivative product polynomial z'(r)
        ///////////////////// /////////////////////

        let f_prime_poly = compute_derivative_poly(
            &chall_minus_ci_evals,
            &f_poly.evaluations(),
            dedup_mle.num_vars(),
        )?;
        let f_prime_p_tr = prover.track_and_commit_mat_mv_poly(&f_prime_poly)?;

        ///////////////////// Compute z(x) and z'(x) = d/dx z(x) /////////////////////
        let z_p = build_root_products(&dedup_mle.evaluations());
        let z_p_prime = d_dx(&z_p);

        ///////////////////// Compute the Bezout polynomials /////////////////////

        let (t_p, s_p) = bez_polys(&z_p, &z_p_prime);
        ///////////////////// Commit to the Bezout polynomials /////////////////////
        let t_p_tr = prover.track_and_commit_mat_uv_poly(t_p)?;

        let s_p_tr = prover.track_and_commit_mat_uv_poly(s_p)?;

        ///////////////////// Sanity check for the Bezout identity /////////////////////

        #[cfg(feature = "honest-prover")]
        {
            // The size of all the polynomials in this protocol, i.e. 2^num_vars
            let poly_size = 2_i32.pow(num_vars as u32) as usize;
            let s_eval = s_p_tr.evaluate_uv(&chall).unwrap();
            let t_eval = t_p_tr.evaluate_uv(&chall).unwrap();
            if f_poly.evaluations().len() >= 2 && f_prime_poly.evaluations().len() >= 2 {
                let f_prime_eval = f_prime_poly.evaluations()[f_prime_poly.evaluations().len() - 2];
                let f_eval = f_poly.evaluations()[poly_size - 2];
                if !(t_eval * f_eval + s_eval * f_prime_eval).is_one() {
                    use ark_piop::prover;

                    return Err(SnarkError::ProverError(
                        prover::errors::ProverError::HonestProverError(
                            prover::errors::HonestProverError::FalseClaim,
                        ),
                    ));
                }
            }
        }

        ///////////////////// Evaluation claims for the Bezout identity
        ///////////////////// /////////////////////
        prover.add_mv_eval_claim(f_p_tr.id(), &f_query_point)?;
        prover.add_mv_eval_claim(f_prime_p_tr.id(), &f_query_point)?;
        prover.add_uv_eval_claim(t_p_tr.id(), chall)?;
        prover.add_uv_eval_claim(s_p_tr.id(), chall)?;

        ///////////////////// Proving the well-formednes of f/////////////////////

        Ok(())
    }

    pub(super) fn verify_nodup_bezout(
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut crate::irs::nodes::VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for NoDup gadget node");
        };

        let Some(input_table) = payload.get(super::INPUT_LABEL).cloned() else {
            panic!("Expected input table for NoDup gadget");
        };

        let tracked_col_oracle = Self::single_col_from_table_oracle(verifier, &input_table)?;
        ///////////////////// Deduplication check /////////////////////
        let defraged_in_tracked_col_oracle =
            Defragmenter::defrag_tracked_col_oracle(verifier, &tracked_col_oracle)?;

        ///////////////////// Some useful variables /////////////////////
        let num_vars = defraged_in_tracked_col_oracle.log_size();
        let f_query_point: Vec<B::F> = if num_vars == 0 {
            Vec::new()
        } else {
            std::iter::once(B::F::zero())
                .chain((0..num_vars - 1).map(|_| B::F::one()))
                .collect()
        };

        if let Some(defraged_activator_tracked_col_oracle) =
            defraged_in_tracked_col_oracle.activator_tracked_oracle()
        {
            let dedup_tr_cm = verifier.track_next_mv_com()?;
            let dedup_wit_tr_cm = &(&dedup_tr_cm
                - &defraged_in_tracked_col_oracle.data_tracked_oracle())
                * &defraged_activator_tracked_col_oracle;
            verifier.add_mv_zerocheck_claim(dedup_wit_tr_cm.id());
        }

        ///////////////////// Compute the challenge /////////////////////
        let chall: B::F = verifier.get_and_append_challenge(b"bezout")?;

        ///////////////////// Track commitments /////////////////////
        let f_p_cm = verifier.track_next_mv_com()?;
        let f_prime_p_cm = verifier.track_next_mv_com()?;
        let t_p_tr = verifier.track_next_uv_com()?;
        let s_p_tr = verifier.track_next_uv_com()?;

        if num_vars > 0 {
            let f_eval = verifier
                .query_mv(f_p_cm.id(), f_query_point.clone())
                .unwrap();
            let f_prime_eval = verifier.query_mv(f_prime_p_cm.id(), f_query_point).unwrap();
            let t_eval = verifier.query_uv(t_p_tr.id(), chall).unwrap();
            let s_eval = verifier.query_uv(s_p_tr.id(), chall).unwrap();

            if !(t_eval * f_eval + s_eval * f_prime_eval).is_one() {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed("Bezout identity check failed".to_string()),
                ));
            }
        }

        Ok(())
    }

    pub(super) fn honest_check_no_dup_active(
        _prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut ProverGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for NoDup gadget node");
        };

        let Some(input_table) = payload.get(super::INPUT_LABEL).cloned() else {
            panic!("Expected input table for NoDup gadget");
        };

        let data_indices = input_table.data_tracked_polys_indices();
        let data_evals: Vec<Vec<B::F>> = data_indices
            .iter()
            .copied()
            .map(|idx| {
                input_table
                    .tracked_col_by_ind(idx)
                    .data_tracked_poly()
                    .evaluations()
            })
            .collect();
        let mut seen = std::collections::HashSet::new();
        let num_rows = input_table.size();
        let activator = input_table
            .activator_tracked_poly()
            .map(|poly| poly.evaluations());

        for row in 0..num_rows {
            if let Some(act) = activator.as_ref()
                && act[row].is_zero()
            {
                continue;
            }
            let tuple: Vec<B::F> = data_evals.iter().map(|col| col[row]).collect();
            if !seen.insert(tuple) {
                return Err(SnarkError::ProverError(
                    ark_piop::prover::errors::ProverError::HonestProverError(
                        ark_piop::prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
            }
        }

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

fn p_prep<B: SnarkBackend>(
    rng: &mut dyn RngCore,
    in_col: &TrackedCol<B>,
) -> SnarkResult<MLE<B::F>> {
    // TODO: Fix this
    let mut evals = in_col.data_tracked_poly().evaluations();
    let random_values: Vec<B::F> = (0..evals.len()).map(|_| B::F::rand(rng)).collect();

    if let Some(activator_tracked_poly) = in_col.activator_tracked_poly() {
        evals = in_col
            .data_tracked_poly()
            .evaluations()
            .par_iter()
            .zip(activator_tracked_poly.evaluations().par_iter())
            .enumerate()
            .map(|(i, (eval, is_activator))| {
                if is_activator.is_zero() {
                    random_values[i]
                } else {
                    *eval
                }
            })
            .collect();
    }

    Ok(MLE::from_evaluations_vec(
        in_col.data_tracked_poly().log_size(),
        evals,
    ))
}

/// Compute the product polynomial $f(X): \mathbb{F}^{\mu+1}\to\mathbb{F}$ such
/// that $$ f(X)=[(1-x_1)\cdot p(x_2, ..., x_n, 0) + x_1\cdot f(x_2, ..., x_n,
/// 0)]\times [(1-x_1)\times p(x_2, ..., x_n, 1) + x_1\times f(x_2, ..., x_n,
/// 1)]$$ on the boolean hypercube {0,1}^n
///
/// The caller needs to check num_vars matches in f and g
/// Cost: linear in N.
pub(super) fn compute_product_poly<F: PrimeField>(
    evals: &[F],
    num_vars: usize,
) -> SnarkResult<MLE<F>> {
    // ===================================
    // prod(x)
    // ===================================
    //
    // `prod(x)` can be computed via recursing the following formula for 2^n-1
    // times
    //
    // `prod(x_1, ..., x_n) :=
    //      [(1-x1)*p(x2, ..., xn, 0) + x1*prod(x2, ..., xn, 0)] *
    //      [(1-x1)*p(x2, ..., xn, 1) + x1*prod(x2, ..., xn, 1)]`
    //
    // At any given step, the right hand side of the equation
    // is available via either p_x or the current view of prod_x
    let mut prod_x_evals = vec![];
    for x in 0..(1 << num_vars) - 1 {
        // sign will decide if the evaluation should be looked up from p_x or
        // prod_x; x_zero_index is the index for the evaluation (x_2, ..., x_n,
        // 0); x_one_index is the index for the evaluation (x_2, ..., x_n, 1);
        let (x_zero_index, x_one_index, sign) = index(x, num_vars);
        if !sign {
            prod_x_evals.push(evals[x_zero_index] * evals[x_one_index]);
        } else {
            // sanity check: if we are trying to look up from the prod_x_evals table,
            // then the target index must already exist
            if x_zero_index >= prod_x_evals.len() || x_one_index >= prod_x_evals.len() {
                return Err(SnarkError::Artifact(format!(
                    "compute_product_poly: index out of bounds at x={x} (x_zero={x_zero_index}, x_one={x_one_index}, len={})",
                    prod_x_evals.len()
                )));
            }
            prod_x_evals.push(prod_x_evals[x_zero_index] * prod_x_evals[x_one_index]);
        }
    }

    // prod(1, 1, ..., 1) := 0
    prod_x_evals.push(F::zero());
    Ok(MLE::from_evaluations_vec(num_vars, prod_x_evals))
}

/// Compute the product polynomial $f'(X): \mathbb{F}^{\mu+1}\to\mathbb{F}$ such
/// that $$ f(X)=[(1-x_1)\cdot p(x_2, ..., x_n, 0) + x_1\cdot f(x_2, ..., x_n,
/// 0)]\times [(1-x_1)\times p(x_2, ..., x_n, 1) + x_1\times f(x_2, ..., x_n,
/// 1)]$$ on the boolean hypercube {0,1}^n
///
///
/// The caller needs to check num_vars matches in f and g
/// Cost: linear in N.
pub(super) fn compute_derivative_poly<F: PrimeField>(
    p_evals: &[F],
    f_evals: &[F],
    num_vars: usize,
) -> SnarkResult<MLE<F>> {
    // TODO: Check the sizes
    // ===================================
    // prod(x)
    // ===================================
    //
    // `prod(x)` can be computed via recursing the following formula for 2^n-1
    // times
    //
    // `prod(x_1, ..., x_n) :=
    //      [(1-x1)*p(x2, ..., xn, 0) + x1*prod(x2, ..., xn, 0)] *
    //      [(1-x1)*p(x2, ..., xn, 1) + x1*prod(x2, ..., xn, 1)]`
    //
    // At any given step, the right hand side of the equation
    // is available via either p_x or the current view of prod_x
    let mut f_prime_evals = vec![];
    for x in 0..(1 << num_vars) - 1 {
        // sign will decide if the evaluation should be looked up from p_x or
        // prod_x; x_zero_index is the index for the evaluation (x_2, ..., x_n,
        // 0); x_one_index is the index for the evaluation (x_2, ..., x_n, 1);
        let (x_zero_index, x_one_index, sign) = index(x, num_vars);
        if !sign {
            f_prime_evals.push(p_evals[x_zero_index] + p_evals[x_one_index]);
        } else {
            // sanity check: if we are trying to look up from the prod_x_evals table,
            // then the target index must already exist
            if x_zero_index >= f_prime_evals.len() || x_one_index >= f_prime_evals.len() {
                return Err(SnarkError::Artifact(format!(
                    "compute_derivative_poly: index out of bounds at x={x} (x_zero={x_zero_index}, x_one={x_one_index}, len={})",
                    f_prime_evals.len()
                )));
            }
            f_prime_evals.push(
                f_evals[x_zero_index] * f_prime_evals[x_one_index]
                    + f_prime_evals[x_zero_index] * f_evals[x_one_index],
            );
        }
    }

    // prod(1, 1, ..., 1) := 0
    f_prime_evals.push(F::zero());

    Ok(MLE::from_evaluations_vec(num_vars, f_prime_evals))
}

// This can be improved
pub fn build_root_products<F: FftField>(roots: &[F]) -> LDE<F> {
    let l = roots.len();

    if l == 1 {
        return LDE::from_coefficients_vec(vec![-roots[0], F::one()]);
    }

    let mid = l / 2;
    let (left, right) = roots.split_at(mid);

    #[cfg(not(feature = "parallel"))]
    {
        let left_poly = build_root_products(left);
        let right_poly = build_root_products(right);
    }

    #[cfg(feature = "parallel")]
    // Parallelize the recursive calls using Rayon
    let (left_poly, right_poly) = rayon::join(
        || build_root_products(left),  // Run in parallel
        || build_root_products(right), // Run in parallel
    );

    left_poly * right_poly
}

pub fn d_dx<F: PrimeField>(poly: &LDE<F>) -> LDE<F> {
    // Skip the constant term and parallelize the computation of the derivative
    let coeffs: Vec<F> = cfg_iter!(poly.coeffs)
        .enumerate() // Get the index for each coefficient
        .skip(1) // Skip the constant term since its derivative is 0
        .map(|(i, coeff)| F::from(i as u64) * coeff) // Derivative: i * coeff[i]
        .collect();

    LDE { coeffs }
}
// -----------------------------------------------------------------------------
// A small helper trait to unify parallel + / - / * on LDE.
// You can also just call `poly_add_par`, etc. directly.
// -----------------------------------------------------------------------------
// trait PolyParOps<F: FftField> {
//     fn par_add(&self, rhs: &Self) -> Self;
//     fn par_sub(&self, rhs: &Self) -> Self;
//     fn par_mul(&self, rhs: &Self) -> Self;
// }

// impl<F: FftField> PolyParOps<F> for LDE<F> {
//     fn par_add(&self, rhs: &Self) -> Self {
//         poly_add_par(self, rhs)
//     }
//     fn par_sub(&self, rhs: &Self) -> Self {
//         poly_sub_par(self, rhs)
//     }
//     fn par_mul(&self, rhs: &Self) -> Self {
//         poly_mul_par(self, rhs)
//     }
// }

// -----------------------------------------------------------------------------
// 4) A "classical" extended GCD for small-degree polynomials, using parallel
//    polynomial ops. (You could do it purely sequentially if you prefer.)
// -----------------------------------------------------------------------------
fn classical_xgcd_polynomials_par<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    // Base case
    if b.is_zero() {
        let gcd_val = a.coeffs[0];
        let gcd_inv = gcd_val.inverse().unwrap();
        return (LDE::from_coefficients_vec(vec![gcd_inv]), LDE::zero());
    }

    let a_dsp = DenseOrSparsePolynomial::from(a);
    let b_dsp = DenseOrSparsePolynomial::from(b);
    let (q, r) = a_dsp.divide_with_q_and_r(&b_dsp).unwrap();

    let (f_sub, g_sub) = classical_xgcd_polynomials_par(b, &r);

    // Combine
    let qg = q * (&g_sub);
    let next_g = f_sub - (&qg);
    (g_sub, next_g)
}

// -----------------------------------------------------------------------------
// 5) 2×2 "matrix" of polynomials, with parallel multiply
// -----------------------------------------------------------------------------
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

    // Multiply this 2x2 matrix by another 2x2, all in parallel
    fn par_multiply(&self, rhs: &Self) -> Self {
        // We'll compute (a11, a12) in one `rayon::join`, and (a21, a22) in parallel.
        // That spawns two parallel tasks, *each* possibly doing more parallel steps
        // in polynomial multiplication.
        let (res_top, res_bot) = rayon::join(
            // top row: (a11, a12)
            || {
                let a11 = (&self.a11) * (&rhs.a11) + (&self.a12 * (&rhs.a21));
                let a12 = (&self.a11) * (&rhs.a12) + (&self.a12 * (&rhs.a22));
                (a11, a12)
            },
            // bottom row: (a21, a22)
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

    // Apply to a vector (f, g) in parallel => (a11*f + a12*g, a21*f + a22*g)
    fn par_apply(&self, f: &LDE<F>, g: &LDE<F>) -> (LDE<F>, LDE<F>) {
        // Each output can be computed in parallel
        let (out1, out2) = rayon::join(
            || (&self.a11) * (f) + (&self.a12 * (g)),
            || (&self.a21) * (f) + (&self.a22 * (g)),
        );
        (out1, out2)
    }
}

// -----------------------------------------------------------------------------
// 6) partial_gcd_step: repeated Euclidean divisions until deg(r1) ~ half of
//    deg(a), collecting transformations in a 2x2 matrix, but with parallel
//    polynomial ops.
// -----------------------------------------------------------------------------
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

        // Parallel matrix multiplication
        m = m.par_multiply(&step_mat);

        r0 = r1;
        r1 = remainder;
    }

    (m, r0, r1)
}

// -----------------------------------------------------------------------------
// 7) The half-gcd recursion itself, parallel version
// -----------------------------------------------------------------------------
fn half_gcd_polynomials_par<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    // Base case
    if b.is_zero() {
        let gcd_val = a.coeffs[0];
        let gcd_inv = gcd_val.inverse().unwrap();
        return (LDE::from_coefficients_vec(vec![gcd_inv]), LDE::zero());
    }

    // Ensure deg(a) >= deg(b)
    if b.degree() > a.degree() {
        let (f_sub, g_sub) = half_gcd_polynomials_par(b, a);
        // Swap result
        return (g_sub, f_sub);
    }

    // Fallback to classical if degrees are small
    let threshold = 16; // tune
    if a.degree() <= threshold || b.degree() <= threshold {
        return classical_xgcd_polynomials_par(a, b);
    }

    // partial step
    let (m, r0, r1) = partial_gcd_step_par(a, b);

    // recurse on smaller pair
    let (f_sub, g_sub) = half_gcd_polynomials_par(&r0, &r1);

    // "lift" back up
    let (f_res, g_res) = m.par_apply(&f_sub, &g_sub);
    (f_res, g_res)
}

// -----------------------------------------------------------------------------
// 8) Finally, `bez_polys` with the *same signature* as requested, but
//    internally uses our parallel half-GCD approach.
// -----------------------------------------------------------------------------
pub fn bez_polys<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    half_gcd_polynomials_par(a, b)
}
