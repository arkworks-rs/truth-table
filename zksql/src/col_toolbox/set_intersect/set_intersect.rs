use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use crate::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    col_toolbox::{
        col_sum::MultiplicitySumCheck, 
        set_disjoint::set_disjoint::SetDisjointIOP, 
    },
};

/// Assumption: col_a and col_b already contain no duplicate elements
/// This should be checked during preprocessing or an earlier step of the zql proving protocol
/// If A or B has duplicates, it allows bad cases, such as l and m sharing a common element.
pub struct SetIntersectIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(PhantomData<F>, PhantomData<PCS>);

impl <F:PrimeField, PCS: PolynomialCommitmentScheme<F>> SetIntersectIOP<F, PCS> 
where PCS: PolynomialCommitmentScheme<F> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col_a: &Col<F, PCS>,
        col_b: &Col<F, PCS>,
        col_l: &Col<F, PCS>,
        col_m: &Col<F, PCS>,
        col_r: &Col<F, PCS>,
        range_col: &Col<F, PCS>
    ) -> Result<(), PolyIOPErrors> {

        // prove L \mutlisetsum M = A
        MultiplicitySumCheck::<F, PCS>::prove(
            prover_tracker,
            col_l,
            col_m,
            col_a,
        )?;

        // prove M \mutlisetsum R = B
        MultiplicitySumCheck::<F, PCS>::prove(
            prover_tracker,
            col_m,
            col_r,
            col_b,
        )?;

        // Prove L and R are disjoint
        SetDisjointIOP::<F, PCS>::prove(
            prover_tracker,
            col_l,
            col_r,
            range_col,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a: &ColComm<F, PCS>,
        col_b: &ColComm<F, PCS>,
        col_l: &ColComm<F, PCS>,
        col_m: &ColComm<F, PCS>,
        col_r: &ColComm<F, PCS>,
        range_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify L \mutlisetsum M = A
        MultiplicitySumCheck::<F, PCS>::verify(
            verifier_tracker, 
            col_l, 
            col_m, 
            col_a,
        )?;

        // verify M \mutlisetsum R = B
        MultiplicitySumCheck::<F, PCS>::verify(
            verifier_tracker, 
            col_m, 
            col_r, 
            col_b,
        )?;

        // verify L and R are disjoint
        SetDisjointIOP::<F, PCS>::verify(
            verifier_tracker,
            col_l,
            col_r,
            range_col,
        )?;

        Ok(())
    }
}