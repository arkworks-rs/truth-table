use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::bag_eq::bag_eq::BagEqIOP,
};

pub struct BagPrescPermIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagPrescPermIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        fx: &Bag<E, PCS>,
        gx: &Bag<E, PCS>,
        perm: &TrackedPoly<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // check input shape is correct
        if fx.num_vars() != gx.num_vars() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagPrescPermIOP Error: fx and gx have different number of variables".to_string(),
            ));
        }
        if fx.num_vars() != perm.num_vars {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagPrescPermIOP Error:fx and perm have different number of variables".to_string(),
            ));
        }
        let nv = fx.num_vars();

        // get a verifier challenge gamma
        // note: fx, gx, perm are already committed to, so ordered_mle, fhat, ghat, etc are fixed
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

         // create "pre-specified" polynomials: one_mle and ordered_mle (0, 1, 2, 3, ..)
        let one_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]);
        let ordered_evals: Vec<E::ScalarField> = (0..2_usize.pow(nv as u32)).map(|x| E::ScalarField::from(x as u64)).collect();
        let ordered_mle = DenseMultilinearExtension::from_evaluations_vec(nv, ordered_evals);
       
        // calculate f_hat = s+gamma*p and g_hat = t+gamma*q
        let fx_evals = fx.poly.evaluations();
        let gx_evals = gx.poly.evaluations();
        let perm_evals = perm.evaluations();
        let fhat_evals = (0..2_usize.pow(fx.num_vars() as u32)).map(|i| ordered_mle[i] + (gamma * fx_evals[i])).collect::<Vec<_>>();
        let ghat_evals = (0..2_usize.pow(gx.num_vars() as u32)).map(|i| perm_evals[i] + (gamma * gx_evals[i])).collect::<Vec<_>>();
        let fhat_mle = DenseMultilinearExtension::from_evaluations_vec(fx.num_vars(), fhat_evals);
        let ghat_mle = DenseMultilinearExtension::from_evaluations_vec(gx.num_vars(), ghat_evals);

        // set up polynomials in the tracker
        let one_poly = tracker.track_mat_poly(one_mle);
        let ordered_poly = tracker.track_mat_poly(ordered_mle);
        let fhat = tracker.track_and_commit_poly(fhat_mle)?;
        let ghat = tracker.track_and_commit_poly(ghat_mle)?;
        let fhat_bag = Bag::new(fhat, one_poly.clone());
        let ghat_bag = Bag::new(ghat, one_poly.clone());

        // create polynomials for checking fhat and ghat were created correctly
        let fhat_check_poly = ordered_poly.add_poly(&fx.poly.mul_scalar(gamma)).sub_poly(&fhat_bag.poly);
        let ghat_check_poly = perm.add_poly(&gx.poly.mul_scalar(gamma)).sub_poly(&ghat_bag.poly);
        
        // add the delayed prover claims to the tracker
        BagEqIOP::<E, PCS>::prove(tracker, &fhat_bag, &ghat_bag)?;
        tracker.add_zerocheck_claim(fhat_check_poly.id);
        tracker.add_zerocheck_claim(ghat_check_poly.id);

        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        fx: &BagComm<E, PCS>,
        gx: &BagComm<E, PCS>,
        perm: &TrackedComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagPrescPermCheck verify");

        // set up polynomials in the tracker in same style as prover 
        let gamma = tracker.get_and_append_challenge(b"gamma")?;
        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        let ordered_closure = |pt: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {
            let mut res = E::ScalarField::zero();
            for (i, x_i) in pt.iter().enumerate() {
                let base = 2_usize.pow(i as u32);
                res += *x_i * E::ScalarField::from(base as u64);
            }
            Ok(res)
        };
        let ordered_comm = tracker.track_virtual_comm(Box::new(ordered_closure));
        let fhat_id = tracker.get_next_id();
        let fhat_comm = tracker.transfer_prover_comm(fhat_id);
        let ghat_id = tracker.get_next_id();
        let ghat_comm = tracker.transfer_prover_comm(ghat_id);
        let fhat_comm_bag = BagComm::new(fhat_comm, one_comm.clone(), fx.num_vars());
        let ghat_comm_bag = BagComm::new(ghat_comm, one_comm, gx.num_vars());
        let fhat_check_poly = ordered_comm.add_comms(&fx.poly.mul_scalar(gamma)).sub_comms(&fhat_comm_bag.poly);
        let ghat_check_poly = perm.add_comms(&gx.poly.mul_scalar(gamma)).sub_comms(&ghat_comm_bag.poly);
        

        BagEqIOP::<E, PCS>::verify(tracker, &fhat_comm_bag, &ghat_comm_bag)?;
        tracker.add_zerocheck_claim(fhat_check_poly.id);
        tracker.add_zerocheck_claim(ghat_check_poly.id);

        end_timer!(start);
        Ok(())
    }
}