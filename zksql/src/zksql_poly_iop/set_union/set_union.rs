use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::marker::PhantomData;
use std::cmp::max;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_sum::bag_sum::BagSumIOP,
        bag_supp::bag_supp::BagSuppIOP,
    },
};
use ark_std::Zero;

/// Assumption: bag_a and bag_b already contain no duplicate elements
/// This should be checked during preprocessing or an earlier step of the zql proving protocol
/// If A or B has duplicates, the result is not the "Bag Union", 
/// which takes the max multiplicity for each element rather than a sum of multiplicities.
pub struct SetUnionIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> SetUnionIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        union_bag: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // calculate bag_sum = bag_a + bag_b
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

        // create the mles from the evaluation vectors
        let sum_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_evals);
        let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_sel_evals);

        // prove a + b = sum_bag
        let sum_poly = prover_tracker.track_and_commit_poly(sum_mle)?;
        let sum_sel_poly = prover_tracker.track_and_commit_poly(sum_sel_mle)?;
        let sum_bag = &Bag::new(sum_poly, sum_sel_poly);
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_a,
            bag_b, 
            sum_bag,
        )?;
 
        // prove union bag is the supp of sum bag
        BagSuppIOP::<E, PCS>::prove(
            prover_tracker,
            sum_bag,
            union_bag,
            range_bag,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        union_bag: &BagComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify a + b = sum_bag
        let sum_nv = max(bag_a.num_vars(), bag_b.num_vars()) + 1;
        let sum_comm_id = verifier_tracker.get_next_id();
        let sum_comm = verifier_tracker.transfer_prover_comm(sum_comm_id);
        let sum_sel_comm_id = verifier_tracker.get_next_id();
        let sum_sel_comm = verifier_tracker.transfer_prover_comm(sum_sel_comm_id);
        let sum_bag = &BagComm::new(sum_comm, sum_sel_comm, sum_nv);
        BagSumIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_a,
            bag_b, 
            sum_bag,
        )?;

        BagSuppIOP::<E, PCS>::verify(
            verifier_tracker,
            sum_bag,
            union_bag,
            range_bag,
        )?;

        Ok(())
    }
}