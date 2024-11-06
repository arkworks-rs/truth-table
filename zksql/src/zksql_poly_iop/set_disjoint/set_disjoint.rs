use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::marker::PhantomData;
use std::cmp::max;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_sum::bag_sum::BagSumIOP,
        bag_sort::bag_sort::BagStrictSortIOP,
    },
};
use ark_std::Zero;

/// Assumption: bag_a and bag_b already contain no duplicate elements
/// This should be checked during preprocessing or an earlier step of the zql proving protocol
/// If A or B has duplicates, the IOP is not complete. The sort sub-IOP will fail. 
pub struct SetDisjointIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> SetDisjointIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // calculate the bag_sum of bag_a and bag_b
        let bag_sum_nv = max(bag_a.num_vars(), bag_b.num_vars()) + 1;
        let bag_sum_len = 2_usize.pow(bag_sum_nv as u32);
        let mut sum_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
        let mut sum_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
        sum_evals.extend(bag_a.poly.evaluations().iter());
        sum_evals.extend(bag_b.poly.evaluations().iter());
        sum_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - sum_evals.len()]);
        sum_sel_evals.extend(bag_a.selector.evaluations().iter());
        sum_sel_evals.extend(bag_b.selector.evaluations().iter());
        sum_sel_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - sum_sel_evals.len()]);
        // set unused values to zero and sort the sum
        let mut indices: Vec<usize> = (0..bag_sum_len).collect();
        for i in indices.iter() {
            if sum_sel_evals[*i] == E::ScalarField::zero() {
                sum_evals[*i] = E::ScalarField::zero();
            }
        }
        indices.sort_by(|&i, &j| (sum_evals[i], sum_sel_evals[i]).cmp(&(sum_evals[j], sum_sel_evals[j])));
        let sum_evals: Vec<E::ScalarField> = indices.iter().map(|&i| sum_evals[i]).collect();
        let sum_sel_evals: Vec<E::ScalarField> = indices.iter().map(|&i| sum_sel_evals[i]).collect();
        let sum_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_evals);
        let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_sel_evals);
       
        // put the sum into the tracker
        let sum_poly = prover_tracker.track_and_commit_poly(sum_mle)?;
        let sum_sel_poly = prover_tracker.track_and_commit_poly(sum_sel_mle)?;
        let sum_bag = &Bag::new(sum_poly, sum_sel_poly);

        // Prove the bag_sum was created correctly
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_a,
            bag_b, 
            sum_bag,
        )?;

        // Prove the bag_sum is strictly sorted 
        BagStrictSortIOP::<E, PCS>::prove(
            prover_tracker,
            sum_bag,
            range_bag,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // move the sum_bag into the verifier tracker
        let sum_nv = max(bag_a.num_vars(), bag_b.num_vars()) + 1;
        let sum_id = verifier_tracker.get_next_id();
        let sum_comm = verifier_tracker.transfer_prover_comm(sum_id);
        let sum_sel_id = verifier_tracker.get_next_id();
        let sum_sel_comm = verifier_tracker.transfer_prover_comm(sum_sel_id);
        let sum_bag = &BagComm::new(sum_comm, sum_sel_comm, sum_nv);

        // verify the bag_sum was created correctly
        BagSumIOP::<E, PCS>::verify(verifier_tracker, bag_a, bag_b, sum_bag)?;

        // verify the bag_sum is strictly sorted 
        BagStrictSortIOP::<E, PCS>::verify(verifier_tracker, sum_bag, range_bag)?;

        Ok(())
    }
}