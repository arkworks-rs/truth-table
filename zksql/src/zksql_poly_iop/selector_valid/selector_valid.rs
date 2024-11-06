
use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use ark_std::One;
use std::ops::Neg;
use crate::subroutines::pcs::PolynomialCommitmentScheme;

use crate::tracker::prelude::*;


pub struct SelectorValidIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> SelectorValidIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E>
{
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        selector: &TrackedPoly<E, PCS>,
    ) -> Result<(),PolyIOPErrors> {

        // set up the tracker and add a zerocheck claim
        let one_minus_sel = selector.mul_scalar(E::ScalarField::one().neg()).add_scalar(E::ScalarField::one());
        let check_poly = selector.mul_poly(&one_minus_sel);
        
        prover_tracker.add_zerocheck_claim(check_poly.id);

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        selector: &TrackedComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let one_minus_sel = selector.mul_scalar(E::ScalarField::one().neg()).add_scalar(E::ScalarField::one());
        let check_poly = selector.mul_comms(&one_minus_sel);
        verifier_tracker.add_zerocheck_claim(check_poly.id);

        Ok(())
    }
}