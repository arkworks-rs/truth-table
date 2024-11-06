use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{One, Zero};
use std::ops::Neg;
use std::marker::PhantomData;
use crate::subroutines::pcs::PolynomialCommitmentScheme;

use crate::tracker::prelude::*;

pub struct BagMultitoolIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagMultitoolIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E>
{
    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        fxs: &[Bag<E, PCS>],
        gxs: &[Bag<E, PCS>],
        mfxs: &[TrackedPoly<E, PCS>],
        mgxs: &[TrackedPoly<E, PCS>],
    ) -> Result<(),PolyIOPErrors> {
        // check input shapes are correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("BagMultitoolIOP Error: fxs is empty".to_string()));
        }
        if fxs.len() != mfxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagMultitoolIOP Error: fxs and mf have different number of polynomials".to_string(),
            ));
        }

        for i in 0..fxs.len() {
            if fxs[i].poly.num_vars() != mfxs[i].num_vars() {
                return Err(PolyIOPErrors::InvalidParameters(
                    "BagMultitoolIOP Error: fxs[i] and mfxs[i] have different number of variables".to_string(),
                ));
            }
        }

        if gxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("BagMultitoolIOP Error: fxs is empty".to_string()));
        }
       
        if gxs.len() != mgxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagMultitoolIOP Error: gxs and mg have different number of polynomials".to_string(),
            ));
        }
        for i in 0..gxs.len() {
            if gxs[i].num_vars() != mgxs[i].num_vars() {
                return Err(PolyIOPErrors::InvalidParameters(
                    "BagMultitoolIOP Error: gxs[i] and mgxs[i] have different number of variables".to_string(),
                ));
            }
        }

        // assumption is that the tracker is already initialized and the polynomials are already tracked
        // so the commitments have already been added to the tracker transcript
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
        tracker: &mut ProverTrackerRef<E, PCS>,
        bag: Bag<E, PCS>,
        m: TrackedPoly<E, PCS>,
        gamma: E::ScalarField,
    ) -> Result<(), PolyIOPErrors> {
        let nv = bag.num_vars();
        
        // construct phat = 1/(bag.p(x) - gamma), i.e. the denominator of the sum
        let p = bag.poly;
        let mut p_evals = p.evaluations().to_vec();
        let mut p_minus_gamma: Vec<<E as Pairing>::ScalarField> = p_evals.iter_mut().map(|x| *x - gamma).collect();
        let phat_evals = p_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(phat_evals);
        let phat_mle = DenseMultilinearExtension::from_evaluations_slice(nv, phat_evals);

        // calculate what the final sum should be
        let m_evals = &m.evaluations();
        let selector_evals = &bag.selector.evaluations();
        let mut v = E::ScalarField::zero();
        for i in 0..2_usize.pow(nv as u32) {
            v += phat_mle[i] * m_evals[i] * selector_evals[i];
        }
        
        // construct the full challenge polynomial by taking phat and multiplying by the selector and multiplicities
        let phat = tracker.track_and_commit_poly(phat_mle)?;
        let sumcheck_challenge_poly = phat.mul_poly(&m).mul_poly(&bag.selector);
       
        // Create Zerocheck claim for procing phat(x) is created correctly, 
        // i.e. ZeroCheck [(p(x)-gamma) * phat(x) - 1] = [(p * phat) - gamma * phat - 1]
        let phat_check_poly = (p.mul_poly(&phat)).sub_poly(&phat.mul_scalar(gamma)).add_scalar(E::ScalarField::one().neg());

        // add the delayed prover claims to the tracker
        tracker.add_sumcheck_claim(sumcheck_challenge_poly.id, v);
        tracker.add_zerocheck_claim(phat_check_poly.id);

        return Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        fxs: &[BagComm<E, PCS>],
        gxs: &[BagComm<E, PCS>],
        mfxs: &[TrackedComm<E, PCS>],
        mgxs: &[TrackedComm<E, PCS>],
    ) -> Result<(), PolyIOPErrors> {
        // check input shapes are correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("BagMultitoolIOP Error: fxs is empty".to_string()));
        }
        if fxs.len() != mfxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagMultitoolIOP Error: fxs and mf have different number of polynomials".to_string(),
            ));
        }
        if gxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("BagMultitoolIOP Error: fxs is empty".to_string()));
        }
       
        if gxs.len() != mgxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagMultitoolIOP Error: fxs and mf have different number of polynomials".to_string(),
            ));
        }

        // create challenges and commitments in same fashion as prover
        // assumption is that proof inputs are already added to the tracker 
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

        // iterate over vector elements and generate subclaims:
        let max_nv_f = fxs.iter().map(|x| x.num_vars()).max().unwrap();
        let max_nv_g = gxs.iter().map(|x| x.num_vars()).max().unwrap();
        let max_nv = max_nv_f.max(max_nv_g);
        let mut lhs_v: E::ScalarField = E::ScalarField::zero();
        let mut rhs_v: E::ScalarField = E::ScalarField::zero();
        for i in 0..fxs.len() {
            let sum_claim_v = Self::verify_generate_subclaims(tracker, fxs[i].clone(), mfxs[i].clone(), gamma)?;
            let ratio = 2_usize.pow((max_nv - fxs[i].num_vars()) as u32);
            let sum_claim_v_adj = sum_claim_v / E::ScalarField::from(ratio as u64);
            lhs_v += sum_claim_v_adj;
        }   

        for i in 0..gxs.len() {
            let sum_claim_v = Self::verify_generate_subclaims(tracker, gxs[i].clone(), mgxs[i].clone(), gamma)?;
            let ratio = 2_usize.pow((max_nv - gxs[i].num_vars()) as u32);
            let sum_claim_v_adj = sum_claim_v / E::ScalarField::from(ratio as u64);
            rhs_v += sum_claim_v_adj;
        } 

        // check that the values of claimed sums are equal
        if lhs_v != rhs_v {
            // println!("ratio1: {}", lhs_v/rhs_v);
            // println!("ratio2: {}", rhs_v/lhs_v);
            let mut err_msg = "BagMutltiTool Verify Error: LHS and RHS have different sums".to_string();
            err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
            return Err(PolyIOPErrors::InvalidVerifier(err_msg));
        }

        Ok(())
    }

    fn verify_generate_subclaims(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        bag: BagComm<E, PCS>,
        m: TrackedComm<E, PCS>,
        gamma: E::ScalarField,
    ) -> Result<E::ScalarField, PolyIOPErrors> {
        let p = bag.poly;
        // get phat mat comm from proof and add it to the tracker
        let phat_id: TrackerID = tracker.get_next_id();
        let phat = tracker.transfer_prover_comm(phat_id);
        
        // make the virtual comms as prover does
        let sumcheck_challenge_comm = phat.mul_comms(&m).mul_comms(&bag.selector);
        let phat_check_poly = (p.mul_comms(&phat)).sub_comms(&phat.mul_scalar(gamma)).add_scalar(E::ScalarField::one().neg());
       

        // add the delayed prover claims to the tracker
        let sum_claim_v = tracker.get_prover_claimed_sum(sumcheck_challenge_comm.id);
        tracker.add_sumcheck_claim(sumcheck_challenge_comm.id, sum_claim_v.clone());
        tracker.add_zerocheck_claim(phat_check_poly.id);

        return Ok(sum_claim_v.clone(),)
    }
}


