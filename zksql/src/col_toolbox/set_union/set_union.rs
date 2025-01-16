use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::marker::PhantomData;
use std::cmp::max;

use crate::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    col_toolbox::{
        col_sum::MultiplicitySumCheck,
        supp_check::supp_check::SuppCheck,
    },
};
use ark_std::Zero;

/// Assumption: col_a and col_b already contain no duplicate elements
/// This should be checked during preprocessing or an earlier step of the zql proving protocol
/// If A or B has duplicates, the result is not the "Col Union", 
/// which takes the max multiplicity for each element rather than a sum of multiplicities.
pub struct SetUnionIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(PhantomData<F>, PhantomData<PCS>);

impl <F:PrimeField, PCS: PolynomialCommitmentScheme<F>> SetUnionIOP<F, PCS> 
where PCS: PolynomialCommitmentScheme<F> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col_a: &Col<F, PCS>,
        col_b: &Col<F, PCS>,
        union_col: &Col<F, PCS>,
        range_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // calculate col_sum = col_a + col_b
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

        // create the mles from the evaluation vectors
        let sum_mle = DenseMultilinearExtension::from_evaluations_vec(col_sum_nv, sum_evals);
        let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(col_sum_nv, sum_sel_evals);

        // prove a + b = sum_col
        let sum_poly = prover_tracker.track_and_commit_poly(sum_mle)?;
        let sum_sel_poly = prover_tracker.track_and_commit_poly(sum_sel_mle)?;
        let sum_col = &Col::new(sum_poly, sum_sel_poly);
        MultiplicitySumCheck::<F, PCS>::prove(
            prover_tracker,
            col_a,
            col_b, 
            sum_col,
        )?;
 
        // prove union col is the supp of sum col
        SuppCheck::<F, PCS>::prove(
            prover_tracker,
            sum_col,
            union_col,
            range_col,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a: &ColComm<F, PCS>,
        col_b: &ColComm<F, PCS>,
        union_col: &ColComm<F, PCS>,
        range_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify a + b = sum_col
        let sum_nv = max(col_a.num_vars(), col_b.num_vars()) + 1;
        let sum_comm_id = verifier_tracker.get_next_id();
        let sum_comm = verifier_tracker.transfer_prover_comm(sum_comm_id);
        let sum_sel_comm_id = verifier_tracker.get_next_id();
        let sum_sel_comm = verifier_tracker.transfer_prover_comm(sum_sel_comm_id);
        let sum_col = &ColComm::new(sum_comm, sum_sel_comm, sum_nv);
        MultiplicitySumCheck::<F, PCS>::verify(
            verifier_tracker,
            col_a,
            col_b, 
            sum_col,
        )?;

        SuppCheck::<F, PCS>::verify(
            verifier_tracker,
            sum_col,
            union_col,
            range_col,
        )?;

        Ok(())
    }
}