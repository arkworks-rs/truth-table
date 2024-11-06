use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_sum::bag_sum::BagSumIOP, 
        set_disjoint::set_disjoint::SetDisjointIOP, 
    },
};

/// Assumption: bag_a and bag_b already contain no duplicate elements
/// This should be checked during preprocessing or an earlier step of the zql proving protocol
/// If A or B has duplicates, it allows bad cases, such as l and m sharing a common element.
pub struct SetIntersectIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> SetIntersectIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        bag_l: &Bag<E, PCS>,
        bag_m: &Bag<E, PCS>,
        bag_r: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>
    ) -> Result<(), PolyIOPErrors> {

        // prove L \mutlisetsum M = A
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_l,
            bag_m,
            bag_a,
        )?;

        // prove M \mutlisetsum R = B
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_m,
            bag_r,
            bag_b,
        )?;

        // Prove L and R are disjoint
        SetDisjointIOP::<E, PCS>::prove(
            prover_tracker,
            bag_l,
            bag_r,
            range_bag,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        bag_l: &BagComm<E, PCS>,
        bag_m: &BagComm<E, PCS>,
        bag_r: &BagComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify L \mutlisetsum M = A
        BagSumIOP::<E, PCS>::verify(
            verifier_tracker, 
            bag_l, 
            bag_m, 
            bag_a,
        )?;

        // verify M \mutlisetsum R = B
        BagSumIOP::<E, PCS>::verify(
            verifier_tracker, 
            bag_m, 
            bag_r, 
            bag_b,
        )?;

        // verify L and R are disjoint
        SetDisjointIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_l,
            bag_r,
            range_bag,
        )?;

        Ok(())
    }
}