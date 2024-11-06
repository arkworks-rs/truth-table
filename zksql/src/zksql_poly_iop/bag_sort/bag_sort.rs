// Prove a bag is strictly sorted 
// by showing it's elements are a subset of [0, 2^n] 
// and the product of its elements is non-zero
// This code as written only proves that the bag is strictly sorted ascending. To prove descending or non-strict requires edits

use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_poly::MultilinearExtension;
use ark_std::{One, Zero};
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::zksql_poly_iop::bag_no_zeros::BagNoZerosIOP;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_presc_perm::bag_presc_perm::BagPrescPermIOP, 
        bag_inclusion::bag_inclusion::BagInclusionIOP,
    },
};

pub struct BagStrictSortIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagStrictSortIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        sorted_bag: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // retrieve some useful values from the inputs
        let range_poly = range_bag.poly.clone();
        let sorted_poly_evals = sorted_bag.poly.evaluations();
        let sorted_nv = sorted_bag.num_vars();
        let sorted_len = sorted_poly_evals.len();
        let range_nv = range_poly.num_vars;
        let range_len = 2_usize.pow(range_nv as u32);
        let p_poly = sorted_bag.poly.clone();
        let p_sel = sorted_bag.selector.clone();

        // create shifted permutation poly for the prescribed permutation check, which shows 
        // q is correctly created based off of p. Then we can use q for calculating diffs in the range check 
        // 	    create first vector s=(0, 1, .., 2^{nv}-1) and another that is the permuted version of it t=(1, .., 2^{nv}-1, 0)
        // 	    (p,q) are p is orig input, q is p left shifted by 1 with wraparound
        let mut shift_perm_evals: Vec<E::ScalarField>  = Vec::<E::ScalarField>::with_capacity(sorted_len);
        shift_perm_evals.extend((1..(sorted_len)).map(|x| E::ScalarField::from(x as u64)));
        shift_perm_evals.push(E::ScalarField::zero());

        let mut q_evals = Vec::<E::ScalarField>::with_capacity(sorted_len);
        q_evals.extend_from_slice(&sorted_poly_evals[1..sorted_len]);
        q_evals.push(*sorted_poly_evals.first().unwrap());

        // Create a difference poly and its selector for the range check, which shows
        // the bag is sorted since the differences are in the correct range 
        //      sorted_bag = [a_0, a_1, ..] from the input
        //      selector = [1, .., 1, 1, 0]
        //      diff_evals = [selector * (q - p) + (1 - selector)] 
        // recall (1 - selector) = [0, 0, .., 0, 1]. Adding it makes the last element of diff_evals non-zero
        // git so we can pass the BagNoZerosIOP check for strictness
        let mut diff_range_sel_evals = vec![E::ScalarField::one(); sorted_len];
        diff_range_sel_evals[sorted_len - 1] = E::ScalarField::zero(); // the last element is allowed to be out of range because of the wraparound
        let diff_evals = (0..sorted_len).map(
            |i| diff_range_sel_evals[i] * (q_evals[i] - sorted_poly_evals[i]) + (E::ScalarField::one() - diff_range_sel_evals[i]) // p-q here made the sign correct? depends on sort order?
        ).collect::<Vec<_>>();
        let diff_range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_range_sel_evals);

        // Set up the tracker and prove the prescribed permutation check
        let one_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![E::ScalarField::one(); sorted_len]);
        let shift_perm_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, shift_perm_evals);
        let q_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, q_evals);
        let one_poly = prover_tracker.track_mat_poly(one_mle);
        let shift_perm_poly = prover_tracker.track_mat_poly(shift_perm_mle); // note: is a precomputed poly
        let q_poly = prover_tracker.track_and_commit_poly(q_mle)?; // is also precomputed??
        let q_bag = Bag::new(q_poly.clone(), one_poly.clone());
        BagPrescPermIOP::<E, PCS>::prove(
            prover_tracker,
            &sorted_bag.clone(),
            &q_bag.clone(),
            &shift_perm_poly.clone(),
        )?;

        // Set up the tracker and prove the range/inclusion check
        let diff_range_sel = prover_tracker.track_mat_poly(diff_range_sel_mle); // note: is a precomputed one-poly
        let diff_range_poly = diff_range_sel.mul_poly(&q_poly.sub_poly(&p_poly)).add_scalar(E::ScalarField::one()).sub_poly(&diff_range_sel);
        #[cfg(debug_assertions)] {
            assert_eq!(diff_range_poly.evaluations(), diff_evals);
        }
        let diff_range_bag = Bag::new(diff_range_poly.clone(), diff_range_sel);
        let range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![E::ScalarField::one(); range_len]);
        let range_sel = prover_tracker.track_mat_poly(range_sel_mle); // note: is a precomputedone-poly
        let range_bag = Bag::new(range_poly.clone(), range_sel);
        BagInclusionIOP::<E, PCS>::prove(
            prover_tracker,
            &diff_range_bag.clone(),
            &range_bag.clone(),
        )?;

        // prove diff contains no zeros
        // TODO: make this an optional check. Sometimes we don't care about strictness 
        let dups_check_bag = Bag::new(diff_range_poly.clone(), p_sel.clone()); // use p_sel instead of diff_range_sel to ignore stuff
        BagNoZerosIOP::<E, PCS>::prove(
            prover_tracker,
            &dups_check_bag,
        )?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        sorted_bag_comm: &BagComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let sorted_nv = sorted_bag_comm.num_vars();
        let sorted_len = 2_usize.pow(sorted_nv as u32);
        let range_nv = range_bag.num_vars();
        let range_comm = range_bag.poly.clone();

        // set up closures specified in the IOP
        let p_comm = sorted_bag_comm.poly.clone();

        let mut shift_perm_evals: Vec<E::ScalarField>  = Vec::<E::ScalarField>::with_capacity(sorted_len);
        shift_perm_evals.extend((1..(sorted_len)).map(|x| E::ScalarField::from(x as u64)));
        shift_perm_evals.push(E::ScalarField::zero());
        let shift_perm_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, shift_perm_evals);
        let shift_perm_closure = move |pt: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(shift_perm_mle.evaluate(pt).unwrap())};
        
        let mut diff_sel_evals = vec![E::ScalarField::one(); sorted_len];
        diff_sel_evals[sorted_len - 1] = E::ScalarField::zero();
        let diff_sel_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_sel_evals);
        let diff_sel_closure = move |pt: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(diff_sel_mle.evaluate(pt).unwrap())};
        
        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        
        
        // set up the tracker and verify the prescribed permutation check
        let one_comm = verifier_tracker.track_virtual_comm(Box::new(one_closure));
        let shift_perm_comm = verifier_tracker.track_virtual_comm(Box::new(shift_perm_closure));
        let q_poly_id = verifier_tracker.get_next_id();
        let q_comm = verifier_tracker.transfer_prover_comm(q_poly_id);
        let q_bag = BagComm::new(q_comm.clone(), one_comm.clone(), sorted_nv);
        BagPrescPermIOP::<E, PCS>::verify(
            verifier_tracker,
            &sorted_bag_comm.clone(),
            &q_bag.clone(),
            &shift_perm_comm.clone(),
        )?;

        // set up the tracker and verify the range check
        let diff_sel_comm = verifier_tracker.track_virtual_comm(Box::new(diff_sel_closure));
        let diff_comm = diff_sel_comm.mul_comms(&q_comm.sub_comms(&p_comm)).add_scalar(E::ScalarField::one()).sub_comms(&diff_sel_comm);
        let diff_bag = BagComm::new(diff_comm.clone(), diff_sel_comm, sorted_nv);
        let range_sel_closure = one_closure.clone();
        let range_sel = verifier_tracker.track_virtual_comm(Box::new(range_sel_closure));
        let range_bag = BagComm::new(range_comm.clone(), range_sel, range_nv);
        BagInclusionIOP::<E, PCS>::verify(
            verifier_tracker,
            &diff_bag.clone(),
            &range_bag.clone(),
        )?;

        // check that diff * diff_inverse - 1 = 0, showing that diff contains no zeros and thus p has no dups
        let no_dups_check_bag = BagComm::new(diff_comm.clone(), sorted_bag_comm.selector.clone(), sorted_nv);
        BagNoZerosIOP::<E, PCS>::verify(
            verifier_tracker,
            &no_dups_check_bag,
        )?;

        Ok(())
    }
}