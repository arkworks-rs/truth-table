#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;

    use crate::subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::set_intersect::set_intersect::SetIntersectIOP,
    };

    fn test_set_intersect() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let range_nums = (0..2_usize.pow(range_nv as u32)).collect::<Vec<usize>>();
        let range_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, range_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // Test good path 1: a and b are same size, no dups
        print!("BagSuppIOP good path 1 test: ");
        let nv = 3;
        let poly_a_nums = (0..2_usize.pow(nv as u32)).collect::<Vec<usize>>();
        let a_sel_nums = vec![1; 2_usize.pow(nv as u32)];
        let poly_b_nums = poly_a_nums.iter().map(|x| x + 3).collect::<Vec<usize>>();
        let b_sel_nums = vec![1; 2_usize.pow(nv as u32)];
        let l_nums = [0, 1, 2, 0, 0, 0, 0, 0];
        let l_sel_nums = [1, 1, 1, 0, 0, 0, 0, 0];
        let mid_nums = vec![3, 4, 5, 6, 7, 0, 0, 0];
        let mid_sel_nums = vec![1, 1, 1, 1, 1, 0, 0, 0];
        let r_nums = vec![8, 9, 10, 0, 0, 0, 0, 0];
        let r_sel_nums = vec![1, 1, 1, 0, 0, 0, 0, 0];
        
        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(nv, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(nv, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(nv, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(nv, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let r_mle = DenseMultilinearExtension::from_evaluations_vec(nv, r_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        test_set_intersect_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle,
            &l_mle,
            &l_sel_mle,
            &mid_mle,
            &mid_sel_mle,
            &r_mle,
            &r_sel_mle,
            &range_mle.clone(),
        )?;
        println!("passed");


        // test good path 2: a and b are different sizes, some dups, non-trivial selector
        print!("BagSuppIOP good path 2 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![1, 2, 8, 0]; 
        let b_sel_nums =    vec![1, 1, 1, 0];
        let l_nums =        vec![0, 3, 4, 5];
        let l_sel_nums =    vec![1, 1, 1, 1];
        let mid_nums =      vec![1, 2];
        let mid_sel_nums =  vec![1, 1];
        let r_nums =        vec![8, 0, 0, 0];
        let r_sel_nums =    vec![1, 0, 0, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let r_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        test_set_intersect_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle,
            &l_mle,
            &l_sel_mle,
            &mid_mle,
            &mid_sel_mle,
            &r_mle,
            &r_sel_mle,
            &range_mle.clone(),
        )?;
        println!("passed");

        // test good path 3: inputs are not sorted
        print!("BagSuppIOP good path 3 test: ");
        let poly_a_nums =   vec![0, 1, 2, 4, 3, 0, 5, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 0, 1, 0];
        let poly_b_nums =   vec![0, 2, 8, 1]; 
        let b_sel_nums =    vec![0, 1, 1, 1];
        let l_nums =        vec![0, 3, 4, 5];
        let l_sel_nums =    vec![1, 1, 1, 1];
        let mid_nums =      vec![1, 2];
        let mid_sel_nums =  vec![1, 1];
        let r_nums =        vec![8, 0, 0, 0];
        let r_sel_nums =    vec![1, 0, 0, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let r_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        test_set_intersect_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle,
            &l_mle,
            &l_sel_mle,
            &mid_mle,
            &mid_sel_mle,
            &r_mle,
            &r_sel_mle,
            &range_mle.clone(),
        )?;
        println!("passed");

        // test bad path 1: diff (l) is missing an element
        print!("BagSuppIOP bad path 1 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![1, 2, 8, 0]; 
        let b_sel_nums =    vec![1, 1, 1, 0];
        let l_nums =        vec![0, 3, 4, 0];
        let l_sel_nums =    vec![1, 1, 1, 0];
        let mid_nums =      vec![1, 2];
        let mid_sel_nums =  vec![1, 1];
        let r_nums =        vec![8, 0, 0, 0];
        let r_sel_nums =    vec![1, 0, 0, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let r_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        let bad_res1 = test_set_intersect_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker.deep_copy(), 
            &mut verifier_tracker.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle,
            &l_mle,
            &l_sel_mle,
            &mid_mle,
            &mid_sel_mle,
            &r_mle,
            &r_sel_mle,
            &range_mle.clone(),
        );
        assert!(bad_res1.is_err());
        println!("passed");

        // test bad path 2: intersection (m) is missing an element
        print!("BagSuppIOP bad path 2 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![1, 2, 8, 0]; 
        let b_sel_nums =    vec![1, 1, 1, 0];
        let l_nums =        vec![0, 3, 4, 5];
        let l_sel_nums =    vec![1, 1, 1, 1];
        let mid_nums =      vec![1, 0];
        let mid_sel_nums =  vec![1, 0];
        let r_nums =        vec![8, 0, 0, 0];
        let r_sel_nums =    vec![1, 0, 0, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let r_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        let bad_res2 = test_set_intersect_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker.deep_copy(), 
            &mut verifier_tracker.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle,
            &l_mle,
            &l_sel_mle,
            &mid_mle,
            &mid_sel_mle,
            &r_mle,
            &r_sel_mle,
            &range_mle.clone(),
        );
        assert!(bad_res2.is_err());
        println!("passed"); 

        // test bad path 3: an element that should be in m is in both l and r instead
        print!("BagSuppIOP bad path 3 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![1, 2, 8, 0]; 
        let b_sel_nums =    vec![1, 1, 1, 0];
        let l_nums =        vec![0, 3, 4, 5, 2, 0, 0, 0];
        let l_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let mid_nums =      vec![1, 0];
        let mid_sel_nums =  vec![1, 0];
        let r_nums =        vec![8, 2, 0, 0];
        let r_sel_nums =    vec![1, 1, 0, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(3, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(1, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let r_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        let bad_res3 = test_set_intersect_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker.deep_copy(), 
            &mut verifier_tracker.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle,
            &l_mle,
            &l_sel_mle,
            &mid_mle,
            &mid_sel_mle,
            &r_mle,
            &r_sel_mle,
            &range_mle.clone(),
        );
        assert!(bad_res3.is_err());
        println!("passed"); 

        Ok(())
    }

    fn test_set_intersect_helper<E: Pairing, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_a_sel: &DenseMultilinearExtension<E::ScalarField>,
        bag_b_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_b_sel: &DenseMultilinearExtension<E::ScalarField>,
        bag_l_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_l_sel: &DenseMultilinearExtension<E::ScalarField>,
        bag_m_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_m_sel: &DenseMultilinearExtension<E::ScalarField>,
        bag_r_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_r_sel: &DenseMultilinearExtension<E::ScalarField>,
        range_poly: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        let bag_a = Bag::new(prover_tracker.track_and_commit_poly(bag_a_poly.clone())?, prover_tracker.track_and_commit_poly(bag_a_sel.clone())?);
        let bag_b = Bag::new(prover_tracker.track_and_commit_poly(bag_b_poly.clone())?, prover_tracker.track_and_commit_poly(bag_b_sel.clone())?);
        let bag_l = Bag::new(prover_tracker.track_and_commit_poly(bag_l_poly.clone())?, prover_tracker.track_and_commit_poly(bag_l_sel.clone())?);
        let bag_m = Bag::new(prover_tracker.track_and_commit_poly(bag_m_poly.clone())?, prover_tracker.track_and_commit_poly(bag_m_sel.clone())?);
        let bag_r = Bag::new(prover_tracker.track_and_commit_poly(bag_r_poly.clone())?, prover_tracker.track_and_commit_poly(bag_r_sel.clone())?);
        let range_bag = Bag::new(prover_tracker.track_and_commit_poly(range_poly.clone())?, prover_tracker.track_and_commit_poly(range_poly.clone())?);

        SetIntersectIOP::<E, PCS>::prove(
            prover_tracker,
            &bag_a,
            &bag_b,
            &bag_l,
            &bag_m,
            &bag_r,
            &range_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        let bag_a_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_a.poly.id), verifier_tracker.transfer_prover_comm(bag_a.selector.id), bag_a.num_vars());
        let bag_b_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_b.poly.id), verifier_tracker.transfer_prover_comm(bag_b.selector.id), bag_b.num_vars());
        let bag_l_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_l.poly.id), verifier_tracker.transfer_prover_comm(bag_l.selector.id), bag_l.num_vars());
        let bag_m_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_m.poly.id), verifier_tracker.transfer_prover_comm(bag_m.selector.id), bag_m.num_vars());
        let bag_r_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_r.poly.id), verifier_tracker.transfer_prover_comm(bag_r.selector.id), bag_r.num_vars());
        let range_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(range_bag.poly.id), verifier_tracker.transfer_prover_comm(range_bag.selector.id), range_bag.num_vars());
        SetIntersectIOP::<E, PCS>::verify(
            verifier_tracker,
            &bag_a_comm,
            &bag_b_comm,
            &bag_l_comm,
            &bag_m_comm,
            &bag_r_comm,
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
    fn set_intersect_test() {
        let res = test_set_intersect();
        res.unwrap();
    }
}