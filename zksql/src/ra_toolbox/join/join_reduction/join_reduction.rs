use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use ark_std::One;
use std::ops::Neg;

use crate::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    col_toolbox::{
        inclusion_check::InclusionCheck, 
        disjoint_check::disjoint_check::DisjointCheck,
        binary_check::binary_check::SelectorValidIOP,
    },
};

pub struct JoinReductionIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(PhantomData<F>, PhantomData<PCS>);

impl <F:PrimeField, PCS: PolynomialCommitmentScheme<F>> JoinReductionIOP<F, PCS> 
where PCS: PolynomialCommitmentScheme<F> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col_a: &Col<F, PCS>,
        col_b: &Col<F, PCS>,
        l_sel: &TrackedPoly<F, PCS>,
        r_sel: &TrackedPoly<F, PCS>,
        range_col: &Col<F, PCS>, // needed for SetDisjointIOP
    ) -> Result<(), PolyIOPErrors> {
        let ma_sel = &l_sel.mul_scalar(F::one().neg()).add_scalar(F::one());
        let mb_sel = &r_sel.mul_scalar(F::one().neg()).add_scalar(F::one());
        let l_col = Col::new(col_a.poly.clone(), col_a.selector.mul_poly(l_sel));
        let r_col = Col::new(col_b.poly.clone(), col_b.selector.mul_poly(r_sel));
        let ma_col = Col::new(col_a.poly.clone(), col_a.selector.mul_poly(ma_sel));
        let mb_col = Col::new(col_b.poly.clone(), col_b.selector.mul_poly(mb_sel));

        // Prove l_sel and r_sel are constructed correctly
        SelectorValidIOP::<F, PCS>::prove(
            prover_tracker,
            l_sel,
        )?;
        SelectorValidIOP::<F, PCS>::prove(
            prover_tracker,
            r_sel,
        )?;

        // Prove L and R are disjoint
        DisjointCheck::<F, PCS>::prove(
            prover_tracker,
            &l_col,
            &r_col,
            &range_col,
        )?;

        // Prove L and M_A are disjoint
        DisjointCheck::<F, PCS>::prove(
            prover_tracker,
            &l_col,
            &ma_col,
            &range_col,
        )?;

        // Prove R and M_B are disjoint
        DisjointCheck::<F, PCS>::prove(
            prover_tracker,
            &r_col,
            &mb_col,
            &range_col,
        )?;

        // prove mid_a and mid_b have the same support
        InclusionCheck::<F, PCS>::prove(
            prover_tracker,
            &ma_col,
            &mb_col,
        )?;
        InclusionCheck::<F, PCS>::prove(
            prover_tracker,
            &mb_col,
            &ma_col,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a: &ColComm<F, PCS>,
        col_b: &ColComm<F, PCS>,
        l_sel: &TrackedComm<F, PCS>,
        r_sel: &TrackedComm<F, PCS>,
        range_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        let ma_sel = &l_sel.mul_scalar(F::one().neg()).add_scalar(F::one());
        let mb_sel = &r_sel.mul_scalar(F::one().neg()).add_scalar(F::one());
        let l_col = ColComm::new(col_a.poly.clone(), col_a.selector.mul_comms(l_sel), col_a.num_vars());
        let r_col = ColComm::new(col_b.poly.clone(), col_b.selector.mul_comms(r_sel), col_b.num_vars());
        let ma_col = ColComm::new(col_a.poly.clone(), col_a.selector.mul_comms(ma_sel), col_a.num_vars());
        let mb_col = ColComm::new(col_b.poly.clone(), col_b.selector.mul_comms(mb_sel), col_b.num_vars());

        // Verify l_sel and r_sel are constructed correctly
        SelectorValidIOP::<F, PCS>::verify(
            verifier_tracker,
            l_sel,
        )?;
        SelectorValidIOP::<F, PCS>::verify(
            verifier_tracker,
            r_sel,
        )?;

        // Verify L and R are disjoint
        DisjointCheck::<F, PCS>::verify(
            verifier_tracker,
            &l_col,
            &r_col,
            &range_col,
        )?;

        // Verify L and M_A are disjoint
        DisjointCheck::<F, PCS>::verify(
            verifier_tracker,
            &l_col,
            &ma_col,
            &range_col,
        )?;

        // Verify R and M_B are disjoint
        DisjointCheck::<F, PCS>::verify(
            verifier_tracker,
            &r_col,
            &mb_col,
            &range_col,
        )?;

        // verify mid_a and mid_b have the same support
        InclusionCheck::<F, PCS>::verify(
            verifier_tracker,
            &ma_col,
            &mb_col,
        )?;
        InclusionCheck::<F, PCS>::verify(
            verifier_tracker,
            &mb_col,
            &ma_col,
        )?;

        Ok(())
    }
}