#[cfg(test)]
mod test;

use arithmetic::{ark_ff, ark_poly};
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_std::{One, Zero};
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use kit::ark_std;
// use zksql_macros::same_nv;
use std::{marker::PhantomData, ops::Neg};

use crate::tracker::prelude::*;

/// Convinces the verifier that for each (fx,gx,mfx,mgx), the multiset of fx
/// elements with multiplicities in mfx is equal to the multiset of gx elements
/// with multiplicities in mgx.
/// This PIOP is based on Logup: https://eprint.iacr.org/2022/1530.pdf
pub struct MultiplicityCheck<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F:PrimeField, PCS: PolynomialCommitmentScheme<F>> MultiplicityCheck<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F:PrimeField
{
    // TODO: #[same_nv(fxs, gxs, mfxs, mgxs)]
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        fxs: &[Col<F, PCS>],
        gxs: &[Col<F, PCS>],
        mfxs: &[TrackedPoly<F, PCS>],
        mgxs: &[TrackedPoly<F, PCS>],
    ) -> Result<(), PolyIOPErrors> {
        // Step 1: Check input shapes are correct

        // Check that we do actually have some polynomial on the left hand side
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs is empty".to_string(),
            ));
        }
        // Check that we have as many multiplicity polynomials as we do polynomials on
        // the left side
        if fxs.len() != mfxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs and mf have different number of polynomials"
                    .to_string(),
            ));
        }

        // Check that we do actually have some polynomial on the right hand side
        if gxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs is empty".to_string(),
            ));
        }
        // Check that we have as many multiplicity polynomials as we do polynomials on
        // the right side
        if gxs.len() != mgxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: gxs and mg have different number of polynomials"
                    .to_string(),
            ));
        }


        // Get the challenge gamma for the check -- Gamma appears in the denominator of
        // the sum assumption is that the tracker is already initialized and the
        // polynomials are already tracked so the commitments have already been
        // added to the tracker transcript
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

        // iterate over vector elements and generate subclaims:
        for i in 0..fxs.len() {
            Self::prove_generate_subclaims(tracker, fxs[i].clone(), mfxs[i].clone(), gamma)?;
        }

        for i in 0..gxs.len() {
            Self::prove_generate_subclaims(tracker, gxs[i].clone(), mgxs[i].clone(), gamma)?;
        }

        Ok(())
    }

    fn prove_generate_subclaims(
        tracker: &mut ProverTrackerRef<F, PCS>,
        col: Col<F, PCS>,
        m: TrackedPoly<F, PCS>,
        gamma: F,
    ) -> Result<(), PolyIOPErrors> {
        let nv = col.num_vars();

        // construct phat = 1/(col.p(x) - gamma), i.e. the denominator of the sum
        // TODO: Should we put the selector in the denominator (with phat) or the
        // nominoator?
        let p = col.inner_poly;
        let mut p_evals = p.evaluations().to_vec();
        let mut p_minus_gamma: Vec<F> =
            p_evals.iter_mut().map(|x| *x - gamma).collect();
        let phat_evals = p_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(phat_evals);
        let phat_mle = DenseMultilinearExtension::from_evaluations_slice(nv, phat_evals);

        // calculate what the final sum should be
        let m_evals = &m.evaluations();
        let selector_evals = &col.actv_poly.evaluations();
        let mut v = F::zero();
        for i in 0..2_usize.pow(nv as u32) {
            v += phat_mle[i] * m_evals[i] * selector_evals[i];
        }

        // construct the full challenge polynomial by taking phat and multiplying by the
        // selector and multiplicities
        let phat = tracker.track_and_commit_poly(phat_mle)?;
        let sumcheck_challenge_poly = phat.mul_poly(&m).mul_poly(&col.actv_poly);

        // Create Zerocheck claim for procing phat(x) is created correctly,
        // i.e. ZeroCheck [(p(x)-gamma) * phat(x) - 1] = [(p * phat) - gamma * phat - 1]
        let phat_check_poly = (p.mul_poly(&phat))
            .sub_poly(&phat.mul_scalar(gamma))
            .add_scalar(F::one().neg());

        // add the delayed prover claims to the tracker
        tracker.add_sumcheck_claim(sumcheck_challenge_poly.id, v);
        tracker.add_zerocheck_claim(phat_check_poly.id);

        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        fxs: &[ColComm<F, PCS>],
        gxs: &[ColComm<F, PCS>],
        mfxs: &[TrackedComm<F, PCS>],
        mgxs: &[TrackedComm<F, PCS>],
    ) -> Result<(), PolyIOPErrors> {
        // check input shapes are correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs is empty".to_string(),
            ));
        }
        if fxs.len() != mfxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs and mf have different number of polynomials"
                    .to_string(),
            ));
        }
        if gxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs is empty".to_string(),
            ));
        }

        if gxs.len() != mgxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs and mf have different number of polynomials"
                    .to_string(),
            ));
        }

        // create challenges and commitments in same fashion as prover
        // assumption is that proof inputs are already added to the tracker
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

        // iterate over vector elements and generate subclaims:
        let max_nv_f = fxs.iter().map(|x| x.num_vars()).max().unwrap();
        let max_nv_g = gxs.iter().map(|x| x.num_vars()).max().unwrap();
        let max_nv = max_nv_f.max(max_nv_g);
        let mut lhs_v: F = F::zero();
        let mut rhs_v: F = F::zero();
        for i in 0..fxs.len() {
            let sum_claim_v =
                Self::verify_generate_subclaims(tracker, fxs[i].clone(), mfxs[i].clone(), gamma)?;
            let ratio = 2_usize.pow((max_nv - fxs[i].num_vars()) as u32);
            let sum_claim_v_adj = sum_claim_v / F::from(ratio as u64);
            lhs_v += sum_claim_v_adj;
        }

        for i in 0..gxs.len() {
            let sum_claim_v =
                Self::verify_generate_subclaims(tracker, gxs[i].clone(), mgxs[i].clone(), gamma)?;
            let ratio = 2_usize.pow((max_nv - gxs[i].num_vars()) as u32);
            let sum_claim_v_adj = sum_claim_v / F::from(ratio as u64);
            rhs_v += sum_claim_v_adj;
        }

        // check that the values of claimed sums are equal
        if lhs_v != rhs_v {
            // println!("ratio1: {}", lhs_v/rhs_v);
            // println!("ratio2: {}", rhs_v/lhs_v);
            let mut err_msg =
                "ColMutltiTool Verify Error: LHS and RHS have different sums".to_string();
            err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
            return Err(PolyIOPErrors::InvalidVerifier(err_msg));
        }

        Ok(())
    }

    fn verify_generate_subclaims(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        col: ColComm<F, PCS>,
        m: TrackedComm<F, PCS>,
        gamma: F,
    ) -> Result<F, PolyIOPErrors> {
        let p = col.poly;
        // get phat mat comm from proof and add it to the tracker
        let phat_id: TrackerID = tracker.get_next_id();
        let phat = tracker.transfer_prover_comm(phat_id);

        // make the virtual comms as prover does
        let sumcheck_challenge_comm = phat.mul_comms(&m).mul_comms(&col.selector);
        let phat_check_poly = (p.mul_comms(&phat))
            .sub_comms(&phat.mul_scalar(gamma))
            .add_scalar(F::one().neg());

        // add the delayed prover claims to the tracker
        let sum_claim_v = tracker.get_prover_claimed_sum(sumcheck_challenge_comm.id);
        tracker.add_sumcheck_claim(sumcheck_challenge_comm.id, sum_claim_v);
        tracker.add_zerocheck_claim(phat_check_poly.id);

        Ok(sum_claim_v)
    }
}
