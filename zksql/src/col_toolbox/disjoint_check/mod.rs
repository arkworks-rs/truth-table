#[cfg(test)]
mod test;
pub mod utils;

use arithmetic::ark_ff;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use std::{cmp::max, marker::PhantomData};

use crate::{
    col_toolbox::{
        disjoint_check::utils::calc_disjoint_check_advice, inclusion_check::InclusionCheck,
        sort_check::StrictSortPIOP,
    },
    tracker::prelude::*,
};

/// A PIOP to prove that the activated rows of two columns are disjoint
pub struct DisjointCheck<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> DisjointCheck<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F: PrimeField,
{
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col_a: &Col<F, PCS>,
        col_b: &Col<F, PCS>,
        range_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let (sum_mle, sum_sel_mle, sum_a_mult_mle, sum_b_mult_mle) =
            calc_disjoint_check_advice(col_a, col_b)?;
        let sum_poly = prover_tracker.track_and_commit_poly(sum_mle)?;
        let sum_sel_poly = prover_tracker.track_and_commit_poly(sum_sel_mle)?;
        let col_c = Col::new(sum_poly.clone(), sum_sel_poly.clone());
        let sum_a_mult_poly = prover_tracker.track_and_commit_poly(sum_a_mult_mle)?;
        let sum_b_mult_poly = prover_tracker.track_and_commit_poly(sum_b_mult_mle)?;

        Self::prove_with_advice(
            prover_tracker,
            col_a,
            col_b,
            &col_c,
            &sum_a_mult_poly,
            &sum_b_mult_poly,
            &range_col,
        )?;

        Ok(())
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col_a: &Col<F, PCS>,
        col_b: &Col<F, PCS>,
        col_c: &Col<F, PCS>,
        m_a: &TrackedPoly<F, PCS>,
        m_b: &TrackedPoly<F, PCS>,
        range_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // Prove col_c is strictly sorted

        // TODO: Actually, we only need to check if it has no duplicate, but strict-sort
        // is the best way we know to do this
        StrictSortPIOP::<F, PCS>::prove(prover_tracker, col_c, range_col)?;

        // Prove the multiplicity vectors use disjoint indices
        let m_mul = m_a.mul_poly(&m_b);
        prover_tracker.add_zerocheck_claim(m_mul.id);

        // prove col_a is included in col_c
        InclusionCheck::<F, PCS>::prove_with_advice(prover_tracker, col_a, col_c, &m_a)?;

        // // prove col_b is included in col_c
        InclusionCheck::<F, PCS>::prove_with_advice(prover_tracker, col_b, col_c, &m_b)?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a: &ColComm<F, PCS>,
        col_b: &ColComm<F, PCS>,
        range_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let col_sum_nv = max(col_a.num_vars(), col_b.num_vars()) + 1;
        // get ids to transfer
        let sum_poly_id = verifier_tracker.get_next_id();
        let col_c_poly = verifier_tracker.transfer_prover_comm(sum_poly_id);
        let sum_sel_poly_id = verifier_tracker.get_next_id();
        let col_c_sel = verifier_tracker.transfer_prover_comm(sum_sel_poly_id);
        let col_c = ColComm::new(col_c_poly, col_c_sel, col_sum_nv);
        let ma_id = verifier_tracker.get_next_id();
        let sum_a_mult_poly = verifier_tracker.transfer_prover_comm(ma_id);
        let mb_id = verifier_tracker.get_next_id();
        let sum_b_mult_poly = verifier_tracker.transfer_prover_comm(mb_id);

        Self::verify_with_advice(
            verifier_tracker,
            col_a,
            col_b,
            &col_c,
            &sum_a_mult_poly,
            &sum_b_mult_poly,
            &range_col,
        )?;

        Ok(())
    }

    pub fn verify_with_advice(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a: &ColComm<F, PCS>,
        col_b: &ColComm<F, PCS>,
        col_c: &ColComm<F, PCS>,
        m_a: &TrackedComm<F, PCS>,
        m_b: &TrackedComm<F, PCS>,
        range_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // verify col_c is strictly sorted
        StrictSortPIOP::<F, PCS>::verify(verifier_tracker, col_c, range_col)?;

        // verify the multiplicity vectors use disjoint indices
        let m_mul = m_a.mul_comms(&m_b);
        verifier_tracker.add_zerocheck_claim(m_mul.id);

        // verify col_a is included in col_c
        InclusionCheck::<F, PCS>::verify_with_advice(verifier_tracker, col_a, col_c, &m_a)?;

        // // verify col_b is included in col_c
        InclusionCheck::<F, PCS>::verify_with_advice(verifier_tracker, col_b, col_c, &m_b)?;

        Ok(())
    }
}
