use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_sum::bag_sum::BagSumIOP, 
        bag_inclusion::bag_inclusion::BagInclusionIOP, 
        set_disjoint::set_disjoint::SetDisjointIOP,
    },
};
/// Assumption: bag_a and bag_b already contain no duplicate elements
/// This should be checked during preprocessing or an earlier step of the zql proving protocol
/// If A or B has duplicates, it allows bad cases, such as l and m sharing a common element.
pub struct SetDiffIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> SetDiffIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        bag_l: &Bag<E, PCS>,
        bag_m: &Bag<E, PCS>,
        bm_multiplicities: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>
    ) -> Result<(), PolyIOPErrors> {

        // Prove L and B are disjoint
        SetDisjointIOP::<E, PCS>::prove(
            prover_tracker,
            bag_l,
            bag_b,
            range_bag,
        )?;

        // prove L \union M = A
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_l,
            bag_m,
            bag_a,
        )?;

        // prove M \subseteq B
        BagInclusionIOP::<E, PCS>::prove_with_advice(
            prover_tracker,
            bag_m,
            bag_b,
            bm_multiplicities,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        bag_l: &BagComm<E, PCS>,
        bag_m: &BagComm<E, PCS>,
        bm_multiplicities: &TrackedComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify L and B are disjoint
        SetDisjointIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_l,
            bag_b,
            range_bag,
        )?;

        // veruft L \union M = A
        BagSumIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_l,
            bag_m,
            bag_a,
        )?;

        // verify M \subseteq B
        BagInclusionIOP::<E, PCS>::verify_with_advice(
            verifier_tracker,
            bag_m,
            bag_b,
            bm_multiplicities,
        )?;

        Ok(())
    }
}