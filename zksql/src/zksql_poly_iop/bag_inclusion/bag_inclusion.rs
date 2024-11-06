use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer};
use std::marker::PhantomData;
use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::tracker::prelude::*;

use crate::zksql_poly_iop::{
    bag_multitool::bag_multitool::BagMultitoolIOP,
    bag_inclusion::utils::calc_bag_inclusion_advice_from_bag,
};

pub struct BagInclusionIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagInclusionIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        included_bag: &Bag<E, PCS>,
        super_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let super_bag_m_mle = calc_bag_inclusion_advice_from_bag(included_bag, super_bag);
        let super_bag_m = tracker.track_and_commit_poly(super_bag_m_mle)?;
        Self::prove_with_advice(tracker, included_bag, super_bag, &super_bag_m)
    }

    pub fn prove_with_advice(
        tracker: &mut ProverTrackerRef<E, PCS>,
        included_bag: &Bag<E, PCS>,
        super_bag: &Bag<E, PCS>,
        super_bag_m: &TrackedPoly<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagInclusionIOP prove");
        let nv = included_bag.num_vars();

        // initialize multiplicity vector
        let one_const_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]);
        let included_bag_m = tracker.track_mat_poly(one_const_mle);

        // call the bag_multitool prover
        BagMultitoolIOP::<E, PCS>::prove(tracker, &[included_bag.clone()], &[super_bag.clone()], &[included_bag_m.clone()], &[super_bag_m.clone()])?;    
        
        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        included_bag: &BagComm<E, PCS>,
        super_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let super_bag_m_id = tracker.get_next_id();
        let super_bag_m = tracker.transfer_prover_comm(super_bag_m_id);
        Self::verify_with_advice(tracker, included_bag, super_bag, &super_bag_m)
    }

    pub fn verify_with_advice(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        included_bag: &BagComm<E, PCS>,
        super_bag: &BagComm<E, PCS>,
        super_bag_m: &TrackedComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagInclusionIOP verify");

        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        BagMultitoolIOP::verify(tracker, &[included_bag.clone()], &[super_bag.clone()], &[one_comm.clone()], &[super_bag_m.clone()])?;
 
        end_timer!(start);
        Ok(())
    }
}