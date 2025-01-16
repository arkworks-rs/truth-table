use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::marker::PhantomData;
use std::cmp::max;

use crate::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    col_toolbox::{
        col_sum::MultiplicitySumCheck,
        sort_check::sort_check::StrictSortPIOP,
    },
};
use ark_std::Zero;

/// Assumption: col_a and col_b already contain no duplicate elements
/// This should be checked during preprocessing or an earlier step of the zql proving protocol
/// If A or B has duplicates, the IOP is not complete. The sort sub-IOP will fail. 
pub struct SetDisjointIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(PhantomData<F>, PhantomData<PCS>);

impl <F:PrimeField, PCS: PolynomialCommitmentScheme<F>> SetDisjointIOP<F, PCS> 
where PCS: PolynomialCommitmentScheme<F> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col_a: &Col<F, PCS>,
        col_b: &Col<F, PCS>,
        range_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // calculate the col_sum of col_a and col_b
        let col_sum_nv = max(col_a.num_vars(), col_b.num_vars()) + 1;
        let col_sum_len = 2_usize.pow(col_sum_nv as u32);
        let mut sum_evals = Vec::<F>::with_capacity(col_sum_len);
        let mut sum_sel_evals = Vec::<F>::with_capacity(col_sum_len);
        sum_evals.extend(col_a.poly.evaluations().iter());
        sum_evals.extend(col_b.poly.evaluations().iter());
        sum_evals.extend(vec![F::zero(); col_sum_len - sum_evals.len()]);
        sum_sel_evals.extend(col_a.selector.evaluations().iter());
        sum_sel_evals.extend(col_b.selector.evaluations().iter());
        sum_sel_evals.extend(vec![F::zero(); col_sum_len - sum_sel_evals.len()]);
        // set unused values to zero and sort the sum
        let mut indices: Vec<usize> = (0..col_sum_len).collect();
        for i in indices.iter() {
            if sum_sel_evals[*i] == F::zero() {
                sum_evals[*i] = F::zero();
            }
        }
        indices.sort_by(|&i, &j| (sum_evals[i], sum_sel_evals[i]).cmp(&(sum_evals[j], sum_sel_evals[j])));
        let sum_evals: Vec<F> = indices.iter().map(|&i| sum_evals[i]).collect();
        let sum_sel_evals: Vec<F> = indices.iter().map(|&i| sum_sel_evals[i]).collect();
        let sum_mle = DenseMultilinearExtension::from_evaluations_vec(col_sum_nv, sum_evals);
        let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(col_sum_nv, sum_sel_evals);
       
        // put the sum into the tracker
        let sum_poly = prover_tracker.track_and_commit_poly(sum_mle)?;
        let sum_sel_poly = prover_tracker.track_and_commit_poly(sum_sel_mle)?;
        let sum_col = &Col::new(sum_poly, sum_sel_poly);

        // Prove the col_sum was created correctly
        MultiplicitySumCheck::<F, PCS>::prove(
            prover_tracker,
            col_a,
            col_b, 
            sum_col,
        )?;

        // Prove the col_sum is strictly sorted 
        StrictSortPIOP::<F, PCS>::prove(
            prover_tracker,
            sum_col,
            range_col,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a: &ColComm<F, PCS>,
        col_b: &ColComm<F, PCS>,
        range_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // move the sum_col into the verifier tracker
        let sum_nv = max(col_a.num_vars(), col_b.num_vars()) + 1;
        let sum_id = verifier_tracker.get_next_id();
        let sum_comm = verifier_tracker.transfer_prover_comm(sum_id);
        let sum_sel_id = verifier_tracker.get_next_id();
        let sum_sel_comm = verifier_tracker.transfer_prover_comm(sum_sel_id);
        let sum_col = &ColComm::new(sum_comm, sum_sel_comm, sum_nv);

        // verify the col_sum was created correctly
        MultiplicitySumCheck::<F, PCS>::verify(verifier_tracker, col_a, col_b, sum_col)?;

        // verify the col_sum is strictly sorted 
        StrictSortPIOP::<F, PCS>::verify(verifier_tracker, sum_col, range_col)?;

        Ok(())
    }
}