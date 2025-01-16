use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use crate::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    col_toolbox::{
        col_sum::MultiplicitySumCheck, 
        inclusion_check::InclusionCheck, 
        set_disjoint::set_disjoint::SetDisjointIOP,
    },
};
/// Assumption: col_a and col_b already contain no duplicate elements
/// This should be checked during preprocessing or an earlier step of the zql proving protocol
/// If A or B has duplicates, it allows bad cases, such as l and m sharing a common element.
pub struct SetDiffIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(PhantomData<F>, PhantomData<PCS>);

impl <F:PrimeField, PCS: PolynomialCommitmentScheme<F>> SetDiffIOP<F, PCS> 
where PCS: PolynomialCommitmentScheme<F> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col_a: &Col<F, PCS>,
        col_b: &Col<F, PCS>,
        col_l: &Col<F, PCS>,
        col_m: &Col<F, PCS>,
        bm_multiplicities: &TrackedPoly<F, PCS>,
        range_col: &Col<F, PCS>
    ) -> Result<(), PolyIOPErrors> {

        // Prove L and B are disjoint
        SetDisjointIOP::<F, PCS>::prove(
            prover_tracker,
            col_l,
            col_b,
            range_col,
        )?;

        // prove L \union M = A
        MultiplicitySumCheck::<F, PCS>::prove(
            prover_tracker,
            col_l,
            col_m,
            col_a,
        )?;

        // prove M \subseteq B
        InclusionCheck::<F, PCS>::prove_with_advice(
            prover_tracker,
            col_m,
            col_b,
            bm_multiplicities,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a: &ColComm<F, PCS>,
        col_b: &ColComm<F, PCS>,
        col_l: &ColComm<F, PCS>,
        col_m: &ColComm<F, PCS>,
        bm_multiplicities: &TrackedComm<F, PCS>,
        range_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify L and B are disjoint
        SetDisjointIOP::<F, PCS>::verify(
            verifier_tracker,
            col_l,
            col_b,
            range_col,
        )?;

        // veruft L \union M = A
        MultiplicitySumCheck::<F, PCS>::verify(
            verifier_tracker,
            col_l,
            col_m,
            col_a,
        )?;

        // verify M \subseteq B
        InclusionCheck::<F, PCS>::verify_with_advice(
            verifier_tracker,
            col_m,
            col_b,
            bm_multiplicities,
        )?;

        Ok(())
    }
}