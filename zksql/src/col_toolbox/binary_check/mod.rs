#[cfg(test)]
mod test;


use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use ark_std::One;
use std::ops::Neg;
use crate::pcs::PolynomialCommitmentScheme;

use crate::tracker::prelude::*;


pub struct SelectorValidIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(PhantomData<F>, PhantomData<PCS>);
impl <F:PrimeField, PCS: PolynomialCommitmentScheme<F>> SelectorValidIOP<F, PCS> 
where PCS: PolynomialCommitmentScheme<F>
{
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        selector: &TrackedPoly<F, PCS>,
    ) -> Result<(),PolyIOPErrors> {

        // set up the tracker and add a zerocheck claim
        let one_minus_sel = selector.mul_scalar(F::one().neg()).add_scalar(F::one());
        let check_poly = selector.mul_poly(&one_minus_sel);
        
        prover_tracker.add_zerocheck_claim(check_poly.id);

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        selector: &TrackedComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let one_minus_sel = selector.mul_scalar(F::one().neg()).add_scalar(F::one());
        let check_poly = selector.mul_comms(&one_minus_sel);
        verifier_tracker.add_zerocheck_claim(check_poly.id);

        Ok(())
    }
}