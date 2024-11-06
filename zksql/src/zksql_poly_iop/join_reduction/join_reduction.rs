use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use ark_std::One;
use std::ops::Neg;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_inclusion::bag_inclusion::BagInclusionIOP, 
        bag_disjoint::bag_disjoint::BagDisjointIOP,
        selector_valid::selector_valid::SelectorValidIOP,
    },
};

pub struct JoinReductionIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> JoinReductionIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        l_sel: &TrackedPoly<E, PCS>,
        r_sel: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>, // needed for SetDisjointIOP
    ) -> Result<(), PolyIOPErrors> {
        let ma_sel = &l_sel.mul_scalar(E::ScalarField::one().neg()).add_scalar(E::ScalarField::one());
        let mb_sel = &r_sel.mul_scalar(E::ScalarField::one().neg()).add_scalar(E::ScalarField::one());
        let l_bag = Bag::new(bag_a.poly.clone(), bag_a.selector.mul_poly(l_sel));
        let r_bag = Bag::new(bag_b.poly.clone(), bag_b.selector.mul_poly(r_sel));
        let ma_bag = Bag::new(bag_a.poly.clone(), bag_a.selector.mul_poly(ma_sel));
        let mb_bag = Bag::new(bag_b.poly.clone(), bag_b.selector.mul_poly(mb_sel));

        // Prove l_sel and r_sel are constructed correctly
        SelectorValidIOP::<E, PCS>::prove(
            prover_tracker,
            l_sel,
        )?;
        SelectorValidIOP::<E, PCS>::prove(
            prover_tracker,
            r_sel,
        )?;

        // Prove L and R are disjoint
        BagDisjointIOP::<E, PCS>::prove(
            prover_tracker,
            &l_bag,
            &r_bag,
            &range_bag,
        )?;

        // Prove L and M_A are disjoint
        BagDisjointIOP::<E, PCS>::prove(
            prover_tracker,
            &l_bag,
            &ma_bag,
            &range_bag,
        )?;

        // Prove R and M_B are disjoint
        BagDisjointIOP::<E, PCS>::prove(
            prover_tracker,
            &r_bag,
            &mb_bag,
            &range_bag,
        )?;

        // prove mid_a and mid_b have the same support
        BagInclusionIOP::<E, PCS>::prove(
            prover_tracker,
            &ma_bag,
            &mb_bag,
        )?;
        BagInclusionIOP::<E, PCS>::prove(
            prover_tracker,
            &mb_bag,
            &ma_bag,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        l_sel: &TrackedComm<E, PCS>,
        r_sel: &TrackedComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        let ma_sel = &l_sel.mul_scalar(E::ScalarField::one().neg()).add_scalar(E::ScalarField::one());
        let mb_sel = &r_sel.mul_scalar(E::ScalarField::one().neg()).add_scalar(E::ScalarField::one());
        let l_bag = BagComm::new(bag_a.poly.clone(), bag_a.selector.mul_comms(l_sel), bag_a.num_vars());
        let r_bag = BagComm::new(bag_b.poly.clone(), bag_b.selector.mul_comms(r_sel), bag_b.num_vars());
        let ma_bag = BagComm::new(bag_a.poly.clone(), bag_a.selector.mul_comms(ma_sel), bag_a.num_vars());
        let mb_bag = BagComm::new(bag_b.poly.clone(), bag_b.selector.mul_comms(mb_sel), bag_b.num_vars());

        // Verify l_sel and r_sel are constructed correctly
        SelectorValidIOP::<E, PCS>::verify(
            verifier_tracker,
            l_sel,
        )?;
        SelectorValidIOP::<E, PCS>::verify(
            verifier_tracker,
            r_sel,
        )?;

        // Verify L and R are disjoint
        BagDisjointIOP::<E, PCS>::verify(
            verifier_tracker,
            &l_bag,
            &r_bag,
            &range_bag,
        )?;

        // Verify L and M_A are disjoint
        BagDisjointIOP::<E, PCS>::verify(
            verifier_tracker,
            &l_bag,
            &ma_bag,
            &range_bag,
        )?;

        // Verify R and M_B are disjoint
        BagDisjointIOP::<E, PCS>::verify(
            verifier_tracker,
            &r_bag,
            &mb_bag,
            &range_bag,
        )?;

        // verify mid_a and mid_b have the same support
        BagInclusionIOP::<E, PCS>::verify(
            verifier_tracker,
            &ma_bag,
            &mb_bag,
        )?;
        BagInclusionIOP::<E, PCS>::verify(
            verifier_tracker,
            &mb_bag,
            &ma_bag,
        )?;

        Ok(())
    }
}