//! A PIOP to check if there are duplicates in a column.
//! # How it works
//! 1. On input column C of size $N=2^\mu$, the prover commits to a column C'
//!    that contains the same active elements as C but random unique elements
//!    for the non-active elements. NoDup for C' implies NoDup for C.
//! 3. The prover and the verifier run a zerocheck on
//!    $activator(x)(c'(x)-c(x))=0$ for all $x\in \mathcal{H}_\mu$
//! 4. The prover computes the univariate polynomial
//!    $z(x)=\prod_{i=0}^{N-1}(x-c'_i)$
//! 5. The prover computes the univariate derivative polynomial
//!    $z'(x)=\frac{d}{dx}z(x)$
//! 6. The prover computes and commits to the Bezout univariate polynomials
//!    $t(x)$ and $s(x)$ such that $$t(x)z(x)+s(x)z'(x)=1$$
//! 7. The verifier samples a random challenge $r\in\mathbb{F}$ and sends it to
//!    the prover.
//! 8. The prover computes and commits to the $\mu$-variate polynomial $f$ such
//!    that $$f(x_0,X)=(1-x_0)\cdot(r-\hat{c'}(X,0))(r-\hat{c'}(X,1)) + x_0\cdot
//!    f(X,0)f(X,1)$$and runs two instances of zerocheck for the above
//!    equations.
//! 9. The prover computes and commits to the $\mu+1$-variate polynomial $f'$
//!    such that $$f'(0,x)=1,\quad f(1,x)=f(x,0)f'(x,1)+f'(x,1)f(x,0)$$and runs
//!    two instances of zerocheck for the above equations.
//! 10. The verifier opens the polynomials $s,t$ at $r$ and $f,f'$ at
//!     $(1,1,\dots,1,0)$ and checks that $$t(r)z(r)+s(r)z'(r)=1$$

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::One;
use ark_ff::Zero;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, errors::VerifierError},
};
use ark_ff::UniformRand;
use ark_std::rand::RngCore;
pub use bezout::bez_polys;
use derivative::Derivative;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::marker::PhantomData;
use utils::{build_root_products, compute_derivative_poly, compute_product_poly, d_dx};

use crate::defragger::Defragmenter;

pub(crate) mod bezout;
#[cfg(test)]
mod test;
pub(crate) mod utils;

pub struct NoDupPIOP<B: SnarkBackend>(PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct NoDupCheckProverInput<B: SnarkBackend> {
    pub col: TrackedCol<B>,
}

impl<B: SnarkBackend> DeepClone<B> for NoDupCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            col: self.col.deep_clone(prover),
        }
    }
}

pub struct NoDupCheckVerifierInput<B: SnarkBackend> {
    pub tracked_col_oracle: TrackedColOracle<B>,
}
impl<B: SnarkBackend> PIOP<B> for NoDupPIOP<B> {
    type ProverInput = NoDupCheckProverInput<B>;
    type VerifierInput = NoDupCheckVerifierInput<B>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        for item in input.col.effective_iter() {
            if !seen.insert(item) {
                return Err(ark_piop::errors::SnarkError::ProverError(
                    ark_piop::prover::errors::ProverError::HonestProverError(
                        ark_piop::prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
            }
        }
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        ///////////////////// Deduplication check /////////////////////
        let defraged_in_col = Defragmenter::defrag_col(prover, &prover_input.col)?;
        ///////////////////// Some useful variables /////////////////////
        // The number of variables in all the polynomials in this protocol
        let num_vars = defraged_in_col.data_tracked_poly().log_size();
        // The size of all the polynomials in this protocol, i.e. 2^num_vars
        let poly_size = 2_i32.pow(num_vars as u32) as usize;
        // The final query point for the polynomial f and f', i.e. (1,1,...,1,0)
        let f_query_point: Vec<B::F> = std::iter::once(B::F::zero())
            .chain((0..num_vars - 1).map(|_| B::F::one()))
            .collect();

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
        let f_eval = f_poly.evaluations()[poly_size - 2];
        let f_p_tr = prover.track_and_commit_mat_mv_poly(&f_poly)?;
        ///////////////////// Compute the derivative product polynomial z'(r)
        ///////////////////// /////////////////////

        let f_prime_poly = compute_derivative_poly(
            &chall_minus_ci_evals,
            &f_poly.evaluations(),
            dedup_mle.num_vars(),
        )?;
        let f_prime_eval = f_prime_poly.evaluations()[f_prime_poly.evaluations().len() - 2];
        let f_prime_p_tr = prover.track_and_commit_mat_mv_poly(&f_prime_poly)?;

        ///////////////////// Compute z(x) and z'(x) = d/dx z(x) /////////////////////
        let z_p = build_root_products(&dedup_mle.evaluations());
        let z_p_prime = d_dx(&z_p);

        ///////////////////// Compute the Bezout polynomials /////////////////////

        let (t_p, s_p) = bez_polys(&z_p, &z_p_prime);
        ///////////////////// Commit to the Bezout polynomials /////////////////////
        let t_p_tr = prover.track_and_commit_mat_uv_poly(t_p)?;
        let t_eval = t_p_tr.evaluate_uv(&chall).unwrap();

        let s_p_tr = prover.track_and_commit_mat_uv_poly(s_p)?;
        let s_eval = s_p_tr.evaluate_uv(&chall).unwrap();

        ///////////////////// Sanity check for the Bezout identity /////////////////////

        #[cfg(feature = "honest-prover")]
        {
            if !(t_eval * f_eval + s_eval * f_prime_eval).is_one() {
                use ark_piop::prover;

                return Err(SnarkError::ProverError(
                    prover::errors::ProverError::HonestProverError(
                        prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
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
    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        ///////////////////// Deduplication check /////////////////////
        let defraged_in_tracked_col_oracle =
            Defragmenter::defrag_tracked_col_oracle(verifier, &verifier_input.tracked_col_oracle)?;
        // let defraged_in_tracked_col_oracle = in_cm;

        ///////////////////// Some useful variables /////////////////////
        // The number of variables in all the polynomials in this protocol
        let num_vars = defraged_in_tracked_col_oracle.log_size();
        // The final query point for the polynomial f and f', i.e. (1,1,...,1,0)
        let f_query_point: Vec<B::F> = std::iter::once(B::F::zero())
            .chain((0..num_vars - 1).map(|_| B::F::one()))
            .collect();

        ///////////////////// Deduplication check /////////////////////
        if let Some(defraged_activator_tracked_col_oracle) =
            defraged_in_tracked_col_oracle.activator_tracked_oracle()
        {
            let dedup_cm_id = verifier.peek_next_id();
            let dedup_tr_cm = verifier.track_mv_com_by_id(dedup_cm_id)?;
            let dedup_wit_tr_cm = &(&dedup_tr_cm
                - &defraged_in_tracked_col_oracle.data_tracked_oracle())
                * &defraged_activator_tracked_col_oracle;
            verifier.add_zerocheck_claim(dedup_wit_tr_cm.id());
        }

        ///////////////////// Compute the challenge /////////////////////
        let chall: B::F = verifier.get_and_append_challenge(b"bezout")?;

        ///////////////////// Get the commitment to f /////////////////////
        let f_p_id = verifier.peek_next_id();
        let _f_p_cm = verifier.track_mv_com_by_id(f_p_id)?;

        ///////////////////// Get the commitment to f' /////////////////////
        let f_prime_p_id = verifier.peek_next_id();
        let _f_prime_p_cm = verifier.track_mv_com_by_id(f_prime_p_id)?;

        ///////////////////// Get the commitment Bezout coeffs /////////////////////
        let t_p_id = verifier.peek_next_id();
        let _t_p_tr = verifier.track_uv_com_by_id(t_p_id)?;
        let s_p_id = verifier.peek_next_id();
        let _s_p_tr = verifier.track_uv_com_by_id(s_p_id)?;

        let f_eval = verifier.query_mv(f_p_id, f_query_point.clone()).unwrap();
        let f_prime_eval = verifier.query_mv(f_prime_p_id, f_query_point).unwrap();
        let t_eval = verifier.query_uv(t_p_id, chall).unwrap();
        let s_eval = verifier.query_uv(s_p_id, chall).unwrap();

        if !(t_eval * f_eval + s_eval * f_prime_eval).is_one() {
            return Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed("Bezout identity check failed".to_string()),
            ));
        }

        ///////////////////// Checking the well-formedness of f /////////////////////
        Ok(())
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
