use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use std::cmp::max;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_inclusion::bag_inclusion::BagInclusionIOP,
        bag_sort::bag_sort::BagStrictSortIOP,
        bag_disjoint::utils::calc_bag_disjoint_advice,
    },
};


pub struct BagDisjointIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagDisjointIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>, 
        bag_a: &Bag<E, PCS>, 
        bag_b: &Bag<E, PCS>, 
        range_bag: &Bag<E, PCS>
    ) -> Result<(), PolyIOPErrors> {
        let (sum_mle, sum_sel_mle, sum_a_mult_mle, sum_b_mult_mle) = calc_bag_disjoint_advice(bag_a, bag_b)?;
        let sum_poly = prover_tracker.track_and_commit_poly(sum_mle)?;
        let sum_sel_poly = prover_tracker.track_and_commit_poly(sum_sel_mle)?;
        let bag_c = Bag::new(sum_poly.clone(), sum_sel_poly.clone());
        let sum_a_mult_poly = prover_tracker.track_and_commit_poly(sum_a_mult_mle)?;
        let sum_b_mult_poly = prover_tracker.track_and_commit_poly(sum_b_mult_mle)?;

        Self::prove_with_advice(
            prover_tracker,
            bag_a,
            bag_b,
            &bag_c,
            &sum_a_mult_poly,
            &sum_b_mult_poly,
            &range_bag,
        )?;

        Ok(())
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        bag_c: &Bag<E, PCS>,
        m_a: &TrackedPoly<E, PCS>,
        m_b: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // Prove bag_c is strictly sorted
        BagStrictSortIOP::<E, PCS>::prove(
            prover_tracker,
            bag_c,
            range_bag,
        )?;

        // Prove the multiplicity vectors use disjoint indices
        let m_mul = m_a.mul_poly(&m_b);
        prover_tracker.add_zerocheck_claim(m_mul.id);

        // prove bag_a is included in bag_c
        BagInclusionIOP::<E, PCS>::prove_with_advice(
            prover_tracker,
            bag_a,
            bag_c,
            &m_a,
        )?;

        // // prove bag_b is included in bag_c
        BagInclusionIOP::<E, PCS>::prove_with_advice(
            prover_tracker,
            bag_b,
            bag_c,
            &m_b,
        )?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let bag_sum_nv = max(bag_a.num_vars(), bag_b.num_vars()) + 1;
        // get ids to transfer
        let sum_poly_id = verifier_tracker.get_next_id();
        let bag_c_poly = verifier_tracker.transfer_prover_comm(sum_poly_id);
        let sum_sel_poly_id = verifier_tracker.get_next_id();
        let bag_c_sel = verifier_tracker.transfer_prover_comm(sum_sel_poly_id);
        let bag_c = BagComm::new(bag_c_poly, bag_c_sel, bag_sum_nv);
        let ma_id = verifier_tracker.get_next_id();
        let sum_a_mult_poly = verifier_tracker.transfer_prover_comm(ma_id);
        let mb_id = verifier_tracker.get_next_id();
        let sum_b_mult_poly = verifier_tracker.transfer_prover_comm(mb_id);

        Self::verify_with_advice(
            verifier_tracker,
            bag_a,
            bag_b,
            &bag_c,
            &sum_a_mult_poly,
            &sum_b_mult_poly,
            &range_bag,
        )?;

        Ok(())
    }

    pub fn verify_with_advice(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        bag_c: &BagComm<E, PCS>,
        m_a: &TrackedComm<E, PCS>,
        m_b: &TrackedComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify bag_c is strictly sorted
        BagStrictSortIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_c,
            range_bag,
        )?; 

        // verify the multiplicity vectors use disjoint indices
        let m_mul = m_a.mul_comms(&m_b);
        verifier_tracker.add_zerocheck_claim(m_mul.id);

        // verify bag_a is included in bag_c
        BagInclusionIOP::<E, PCS>::verify_with_advice(
            verifier_tracker,
            bag_a,
            bag_c,
            &m_a,
        )?;

        // // verify bag_b is included in bag_c
        BagInclusionIOP::<E, PCS>::verify_with_advice(
            verifier_tracker,
            bag_b,
            bag_c,
            &m_b,
        )?;

        Ok(())
    }
}