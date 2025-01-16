#[cfg(test)]
mod test;

use arithmetic::{
    ark_ff::{Field, PrimeField},
    ark_poly::DenseMultilinearExtension,
};
use ark_std::{end_timer, start_timer, One, Zero};
use crypto::ark_ec::pairing::Pairing;
use kit::ark_std;
use std::marker::PhantomData;

use crate::{col_toolbox::eq_check::EqCheckIOP, tracker::prelude::*};
use crypto::pcs::PolynomialCommitmentScheme;
/// A PIOP for checking that the activated rows of the original column are
/// permuted with ther permuation `perm` to get the permuted column.
///
/// Internally, It proves that the the MLE of (index, permuted_col) and (perm,
/// orig_col) are equal. This is done with the help of the `EqCheckIOP`.
/// Note: the i-th element of the permuted_col is the perm[i]-th position
/// of orig_col Example: orig_col = [4,2,7,5,1,0,3,6], permuted_col =
/// [5,2,6,3,4,1,7,0],  perm = [3,1,7,6,0,4,2,5]
pub struct PrescrPermPIOP<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F: Field + PrimeField, PCS: PolynomialCommitmentScheme<F>> PrescrPermPIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F: PrimeField,
{
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        permuted_col: &Col<F, PCS>,
        orig_col: &Col<F, PCS>,
        perm: &TrackedPoly<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // TODO: These length checks appear in many places --> Macro? Function?
        // step1: check input shape is correct
        if permuted_col.num_vars() != orig_col.num_vars() {
            return Err(PolyIOPErrors::InvalidParameters(
                "PrescrPermPIOP Error: permuted_col and orig_col have different number of variables"
                    .to_string(),
            ));
        }
        if permuted_col.num_vars() != perm.num_vars {
            return Err(PolyIOPErrors::InvalidParameters(
                "PrescrPermPIOP Error:permuted_col and perm have different number of variables"
                    .to_string(),
            ));
        }
        let nv = permuted_col.num_vars();

        // step2: get a verifier challenge gamma to mix up the order polynomials and
        // value poltnomials
        // note: permuted_col, orig_col, perm are already committed to, so
        // ordered_mle, fhat, ghat, etc are fixed
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

        // create "pre-specified" polynomials: one_mle and ordered_mle (0, 1, 2, 3, ..)
        let one_mle = DenseMultilinearExtension::from_evaluations_vec(
            nv,
            vec![F::one(); 2_usize.pow(nv as u32)],
        );
        let ordered_evals: Vec<F> = (0..2_usize.pow(nv as u32))
            .map(|x| F::from(x as u64))
            .collect();
        let ordered_mle = DenseMultilinearExtension::from_evaluations_vec(nv, ordered_evals);

        // calculate f_hat = s+gamma*p and g_hat = t+gamma*q
        let permuted_col_evals = permuted_col.inner_poly.evaluations();
        let orig_col_evals = orig_col.inner_poly.evaluations();
        let perm_evals = perm.evaluations();
        let fhat_evals = (0..2_usize.pow(permuted_col.num_vars() as u32))
            .map(|i| ordered_mle[i] + (gamma * permuted_col_evals[i]))
            .collect::<Vec<_>>();
        let ghat_evals = (0..2_usize.pow(orig_col.num_vars() as u32))
            .map(|i| perm_evals[i] + (gamma * orig_col_evals[i]))
            .collect::<Vec<_>>();
        let fhat_mle =
            DenseMultilinearExtension::from_evaluations_vec(permuted_col.num_vars(), fhat_evals);
        let ghat_mle =
            DenseMultilinearExtension::from_evaluations_vec(orig_col.num_vars(), ghat_evals);

        // set up polynomials in the tracker
        let one_poly = tracker.track_mat_poly(one_mle);
        let ordered_poly = tracker.track_mat_poly(ordered_mle);
        let fhat = tracker.track_and_commit_poly(fhat_mle)?;
        let ghat = tracker.track_and_commit_poly(ghat_mle)?;
        // TODO: Why are we activating all of the rows? Rn we're proving the prescribed
        // perm even for non-activated rows. However, we should only be proving the perm
        // for activated rows.
        let fhat_col = Col::new(fhat, one_poly.clone());
        let ghat_col = Col::new(ghat, one_poly.clone());

        // create polynomials for checking fhat and ghat were created correctly
        let fhat_check_poly = ordered_poly
            .add_poly(&permuted_col.inner_poly.mul_scalar(gamma))
            .sub_poly(&fhat_col.inner_poly);
        let ghat_check_poly = perm
            .add_poly(&orig_col.inner_poly.mul_scalar(gamma))
            .sub_poly(&ghat_col.inner_poly);

        // add the delayed prover claims to the tracker
        EqCheckIOP::<F, PCS>::prove(tracker, &fhat_col, &ghat_col)?;
        tracker.add_zerocheck_claim(fhat_check_poly.id);
        tracker.add_zerocheck_claim(ghat_check_poly.id);

        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        permuted_col: &ColComm<F, PCS>,
        orig_col: &ColComm<F, PCS>,
        perm: &TrackedComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "ColPrescrPermPIOP verify");

        // set up polynomials in the tracker in same style as prover
        let gamma = tracker.get_and_append_challenge(b"gamma")?;
        let one_closure = |_: &[F]| -> Result<F, PolyIOPErrors> { Ok(F::one()) };
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        let ordered_closure = |pt: &[F]| -> Result<F, PolyIOPErrors> {
            let mut res = F::zero();
            for (i, x_i) in pt.iter().enumerate() {
                let base = 2_usize.pow(i as u32);
                res += *x_i * F::from(base as u64);
            }
            Ok(res)
        };
        let ordered_comm = tracker.track_virtual_comm(Box::new(ordered_closure));
        let fhat_id = tracker.get_next_id();
        let fhat_comm = tracker.transfer_prover_comm(fhat_id);
        let ghat_id = tracker.get_next_id();
        let ghat_comm = tracker.transfer_prover_comm(ghat_id);
        let fhat_comm_col = ColComm::new(fhat_comm, one_comm.clone(), permuted_col.num_vars());
        let ghat_comm_col = ColComm::new(ghat_comm, one_comm, orig_col.num_vars());
        let fhat_check_poly = ordered_comm
            .add_comms(&permuted_col.poly.mul_scalar(gamma))
            .sub_comms(&fhat_comm_col.poly);
        let ghat_check_poly = perm
            .add_comms(&orig_col.poly.mul_scalar(gamma))
            .sub_comms(&ghat_comm_col.poly);

        EqCheckIOP::<F, PCS>::verify(tracker, &fhat_comm_col, &ghat_comm_col)?;
        tracker.add_zerocheck_claim(fhat_check_poly.id);
        tracker.add_zerocheck_claim(ghat_check_poly.id);

        end_timer!(start);
        Ok(())
    }
}
