
#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;
    
    use std::collections::HashSet;
    use crate::subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;
    use ark_std::{One, Zero, rand::Rng};

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::bag_supp::bag_supp::BagSuppIOP,
    };
    

    fn test_bag_supp() -> Result<(), PolyIOPErrors> {
        // testing params
        let orig_nv = 4;
        let supp_nv = orig_nv - 1;
        let num_range_pow = 10;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, num_range_pow)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create a poly with duplicates and its supp
        let mut set = HashSet::new();
        while set.len() < 2_usize.pow(supp_nv as u32) {
            let num = rng.gen_range(1..1000);
            set.insert(num);
        }
        let mut supp_nums: Vec<i32> = set.into_iter().collect();
        supp_nums.sort();
        let supp_evals = supp_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let supp = DenseMultilinearExtension::from_evaluations_vec(supp_nv, supp_evals);
        let supp_sel = DenseMultilinearExtension::from_evaluations_vec(supp_nv, vec![Fr::one(); 2_usize.pow(supp_nv as u32)]);

        let mut orig_poly_nums = supp_nums.clone();
        orig_poly_nums.append(&mut supp_nums.clone());
        let orig_poly_evals = orig_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let orig_poly = DenseMultilinearExtension::from_evaluations_vec(orig_nv, orig_poly_evals);
        let orig_sel = DenseMultilinearExtension::from_evaluations_vec(orig_nv, vec![Fr::one(); 2_usize.pow(orig_nv as u32)]);

        // create the range poly and its multiplicity vector
        let range_poly_evals = (0..2_usize.pow(num_range_pow as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
        let range_poly = DenseMultilinearExtension::from_evaluations_vec(num_range_pow, range_poly_evals);

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // test good path 1: no use of selectors
        test_bag_supp_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &orig_poly.clone(), &orig_sel.clone(),  &supp.clone(), &supp_sel.clone(), &range_poly.clone())?;
        println!("BagSuppIOP good path 1 test passed");

        // test bad path 1: supp contains a duplicate (i.e. supp is not strictly sorted), but otherwise would pass
        let mut bad1_supp_nums = supp_nums.clone();
        bad1_supp_nums[0] = bad1_supp_nums[1];
        let bad_supp_1_evals = bad1_supp_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let bad_supp_1 = DenseMultilinearExtension::from_evaluations_vec(supp_nv, bad_supp_1_evals);
        let mut bad1_bag_nums = orig_poly_nums.clone();
        bad1_bag_nums[0] = bad1_bag_nums[1];
        bad1_bag_nums[2_usize.pow(supp_nv as u32)] = bad1_bag_nums[1];
        let bad1_bag_evals = bad1_bag_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let bad1_bag = DenseMultilinearExtension::from_evaluations_vec(orig_nv, bad1_bag_evals);
        let bad_result1 = test_bag_supp_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &bad1_bag.clone(), &orig_sel.clone(),  &bad_supp_1.clone(), &supp_sel.clone(), &range_poly.clone());
        assert!(bad_result1.is_err());
        println!("BagSuppIOP bad path 1 test passed");

        // test bad path 2: supp has an element not in orig (i.e. supp has a zero multiplicity)
        let mut bad2_bag_poly_nums = orig_poly_nums.clone();
        bad2_bag_poly_nums[0] = bad2_bag_poly_nums[1];
        bad2_bag_poly_nums[2_usize.pow(supp_nv as u32)] = bad2_bag_poly_nums[1];
        let bad2_bag_poly_evals = bad2_bag_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let bad2_bag_poly = DenseMultilinearExtension::from_evaluations_vec(orig_nv, bad2_bag_poly_evals);
        let bad_result2 = test_bag_supp_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &bad2_bag_poly.clone(), &orig_sel.clone(), &supp.clone(), &supp_sel.clone(), &range_poly.clone());
        assert!(bad_result2.is_err());
        println!("BagSuppIOP bad path 2 test passed");

        // test bad path 3: supp replaces an element in orig with a dup element (i.e. subset BagMultitoolCheck fails becuase missing an orig element)
        let mut bad_supp_nums_3 = supp_nums.clone();
        bad_supp_nums_3[0] = bad_supp_nums_3[1];
        let bad_supp_3_evals = bad_supp_nums_3.iter().map(|x| Fr::from(*x as u64)).collect();
        let bad_supp_3 = DenseMultilinearExtension::from_evaluations_vec(supp_nv, bad_supp_3_evals);
        let mut bad2_common_mset_bag_m_nums = vec![Fr::from(1u64); 2_usize.pow(orig_nv as u32)];
        bad2_common_mset_bag_m_nums[0] = Fr::zero(); 
        bad2_common_mset_bag_m_nums[1] = Fr::from(3u64);
        bad2_common_mset_bag_m_nums[2_usize.pow(supp_nv as u32)] = Fr::zero();
        let bad_result3 = test_bag_supp_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &orig_poly.clone(), &orig_sel.clone(),  &bad_supp_3.clone(), &supp_sel.clone(), &range_poly.clone());
        assert!(bad_result3.is_err());
        println!("BagSuppIOP bad path 3 test passed");

        Ok(())

    }

    fn test_bag_supp_helper<E: Pairing, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_sel: &DenseMultilinearExtension<E::ScalarField>,
        supp_poly: &DenseMultilinearExtension<E::ScalarField>,
        supp_sel: &DenseMultilinearExtension<E::ScalarField>,
        range_poly: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        let range_nv = range_poly.num_vars;
        let bag = Bag::new(prover_tracker.track_and_commit_poly(bag_poly.clone())?, prover_tracker.track_and_commit_poly(bag_sel.clone())?);
        let supp = Bag::new(prover_tracker.track_and_commit_poly(supp_poly.clone())?, prover_tracker.track_and_commit_poly(supp_sel.clone())?);
        let range_poly = prover_tracker.track_and_commit_poly(range_poly.clone())?;
        let range_sel = prover_tracker.track_mat_poly(DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![E::ScalarField::one(); 2_usize.pow(range_nv as u32)]));
        let range_bag = Bag::new(range_poly.clone(), range_sel);

        BagSuppIOP::<E, PCS>::prove(
            prover_tracker,
            &bag,
            &supp,
            &range_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;
        
        // set up verifier tracker, create subclaims, and verify IOPProofs
        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        verifier_tracker.set_compiled_proof(proof);
        let bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag.poly.id), verifier_tracker.transfer_prover_comm(bag.selector.id).clone(), bag.num_vars());
        let supp_comm = BagComm::new(verifier_tracker.transfer_prover_comm(supp.poly.id), verifier_tracker.transfer_prover_comm(supp.selector.id).clone(), supp.num_vars());
        let range_comm = verifier_tracker.transfer_prover_comm(range_poly.id).clone();
        let range_sel_comm = verifier_tracker.track_virtual_comm(Box::new(one_closure));
        let range_bag_comm = BagComm::new(range_comm.clone(), range_sel_comm, range_nv);
        BagSuppIOP::<E, PCS>::verify(
            verifier_tracker,
            &bag_comm,
            &supp_comm,
            &range_bag_comm,
        )?;
        verifier_tracker.verify_claims()?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.id_counter, v_tracker.id_counter);
        assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);
        Ok(())
    }

    #[test]
    fn bag_supp_test() {
        let res = test_bag_supp();
        res.unwrap();
    }
}