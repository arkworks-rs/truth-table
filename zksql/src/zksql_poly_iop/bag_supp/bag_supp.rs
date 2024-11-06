use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_inclusion::bag_inclusion::BagInclusionIOP,
        bag_inclusion::utils::calc_bag_inclusion_advice_from_bag,
        bag_no_zeros::BagNoZerosIOP,
        bag_sort::bag_sort::BagStrictSortIOP,
    },
};

pub struct BagSuppIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSuppIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag: &Bag<E, PCS>,
        supp: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        let common_mset_supp_m_mle = calc_bag_inclusion_advice_from_bag(bag, supp);
        let common_mset_supp_m = prover_tracker.track_and_commit_poly(common_mset_supp_m_mle)?;
    
        BagSuppIOP::prove_with_advice(
            prover_tracker, 
            bag, 
            supp, 
            &common_mset_supp_m, 
            range_bag
        )?;
    
        Ok(())
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag: &Bag<E, PCS>,
        supp: &Bag<E, PCS>,
        common_mset_supp_m: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // Show bag \subseteq supp
        BagInclusionIOP::<E, PCS>::prove_with_advice(
            prover_tracker,
            &bag.clone(),
            &supp.clone(),
            &common_mset_supp_m.clone(),
        )?;
    
        // Show common_mset_supp_m has no zeros, which implies supp \subseteq bag
        // common_mset_supp_m will have no zeros becuaes it's the only way to for it to be valid
        // otherwise calc_bag_inclusion_advice_from_bag would not return something without zeros by default
        // Note: can resuse the supp.selector as the supp_m.selector
        let supp_no_dups_checker = Bag::new(common_mset_supp_m.clone(), supp.selector.clone());
        BagNoZerosIOP::<E, PCS>::prove(
            prover_tracker,
            &supp_no_dups_checker,
        )?;
    
        // (BagStrictSortIOP) Show supp is sorted by calling bag_sort
        BagStrictSortIOP::<E, PCS>::prove(
            prover_tracker,
            supp,
            range_bag,
        )?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag: &BagComm<E, PCS>,
        supp: &BagComm<E, PCS>,
        range_bag_comm: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        let common_mset_supp_m_id = verifier_tracker.get_next_id();
        let common_mset_supp_m = verifier_tracker.transfer_prover_comm(common_mset_supp_m_id);

        BagSuppIOP::verify_with_advice(
            verifier_tracker, 
            bag, 
            supp, 
            &common_mset_supp_m, 
            range_bag_comm
        )?;

        Ok(())
    }

    pub fn verify_with_advice(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag: &BagComm<E, PCS>,
        supp: &BagComm<E, PCS>,
        common_mset_supp_m: &TrackedComm<E, PCS>,
        range_bag_comm: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // Use BagMultitool PIOP to show bag and supp share a Common Multiset
        BagInclusionIOP::<E, PCS>::verify_with_advice(
            verifier_tracker,
            &bag.clone(),
            &supp.clone(),
            &common_mset_supp_m.clone(),
        )?;
    
        // bag and supp are subsets of each other by showing multiplicity polys have no zeros
        let supp_no_dups_checker = BagComm::new(common_mset_supp_m.clone(), supp.selector.clone(), supp.num_vars());
        BagNoZerosIOP::<E, PCS>::verify(
            verifier_tracker,
            &supp_no_dups_checker,
        )?;
    
        // (BagStrictSortIOP) Show supp is sorted by calling bag_sort
        BagStrictSortIOP::<E, PCS>::verify(
            verifier_tracker,
            supp,
            range_bag_comm,
        )?;

        Ok(())
    }
}