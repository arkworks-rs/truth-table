// use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ec::pairing::Pairing;
use ark_ff::batch_inversion;
use ark_poly::DenseMultilinearExtension;
use std::marker::PhantomData;
use crate::subroutines::pcs::PolynomialCommitmentScheme;

use crate::tracker::prelude::*;


pub struct BagNoZerosIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagNoZerosIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E>
{
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag: &Bag<E, PCS>,
    ) -> Result<(),PolyIOPErrors> {

        // compute inverses of bag.poly
        let bag_poly = bag.poly.clone();
        let bag_sel = bag.selector.clone();
        let bag_poly_evals = bag.poly.evaluations();
        let mut eval_inverses = bag_poly_evals.clone();
        batch_inversion(&mut eval_inverses);
        let inverses_mle = DenseMultilinearExtension::from_evaluations_vec(bag.num_vars(),eval_inverses);

        // set up the tracker and add a zerocheck claim
        let inverses_poly = prover_tracker.track_and_commit_poly(inverses_mle)?;
        let no_dups_check_poly = bag_poly.mul_poly(&bag_sel).mul_poly(&inverses_poly).sub_poly(&bag_sel);
        
        prover_tracker.add_zerocheck_claim(no_dups_check_poly.id);

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let bag_poly = bag.poly.clone();
        let bag_sel = bag.selector.clone();
        let inverses_poly_id = verifier_tracker.get_next_id();
        let inverses_poly = verifier_tracker.transfer_prover_comm(inverses_poly_id);
        let no_dups_check_poly = bag_poly.mul_comms(&bag_sel).mul_comms(&inverses_poly).sub_comms(&bag_sel);
        verifier_tracker.add_zerocheck_claim(no_dups_check_poly.id);

        Ok(())
    }
}


