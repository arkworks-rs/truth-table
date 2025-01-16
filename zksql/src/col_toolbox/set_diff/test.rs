#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;

    use crate::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        col_toolbox::set_diff::set_diff::SetDiffIOP,
    };

    fn test_set_diff() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let range_nums = (0..2_usize.pow(range_nv as u32)).collect::<Vec<usize>>();
        let range_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, range_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // Test good path 1: a and b are same size, no dups
        print!("SuppCheck good path 1 test: ");
        let nv = 3;
        let poly_a_nums = (0..2_usize.pow(nv as u32)).collect::<Vec<usize>>();
        let a_sel_nums = vec![1; 2_usize.pow(nv as u32)];
        let poly_b_nums = poly_a_nums.iter().map(|x| x + 3).collect::<Vec<usize>>();
        let b_sel_nums = vec![1; 2_usize.pow(nv as u32)];
        let l_nums = [0, 1, 2, 0, 0, 0, 0, 0];
        let l_sel_nums = [1, 1, 1, 0, 0, 0, 0, 0];
        let mid_nums = vec![3, 4, 5, 6, 7, 0, 0, 0];
        let mid_sel_nums = vec![1, 1, 1, 1, 1, 0, 0, 0];
        let bm_multiplicities = vec![1, 1, 1, 1, 1, 0, 0, 0];
        
        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(nv, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(nv, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(nv, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(nv, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let bm_multiplicities_mle = DenseMultilinearExtension::from_evaluations_vec(nv, bm_multiplicities.iter().map(|x| Fr::from(*x as u64)).collect());

        test_set_diff_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
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
            &bm_multiplicities_mle,
            &range_mle.clone(),
        )?;
        println!("passed");


        // test good path 2: a and b are different sizes, some dups, non-trivial selector
        print!("SuppCheck good path 2 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![1, 2, 3, 0]; 
        let b_sel_nums =    vec![1, 1, 1, 0];
        let l_nums =        vec![0, 4, 5, 0];
        let l_sel_nums =    vec![1, 1, 1, 0];
        let mid_nums =      vec![1, 2, 3, 0];
        let mid_sel_nums =  vec![1, 1, 1, 0];
        let bm_multiplicities = vec![1, 1, 1, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(2, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let bm_multiplicities_mle = DenseMultilinearExtension::from_evaluations_vec(2, bm_multiplicities.iter().map(|x| Fr::from(*x as u64)).collect());

        test_set_diff_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
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
            &bm_multiplicities_mle,
            &range_mle.clone(),
        )?;
        println!("passed");

        // test good path 3: inputs are not sorted
        print!("SuppCheck good path 3 test: ");
        let poly_a_nums =   vec![0, 1, 2, 4, 3, 0, 5, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 0, 1, 0];
        let poly_b_nums =   vec![0, 2, 3, 1]; 
        let b_sel_nums =    vec![0, 1, 1, 1];
        let l_nums =        vec![0, 4, 5, 0];
        let l_sel_nums =    vec![1, 1, 1, 0];
        let mid_nums =      vec![1, 2, 3, 0];
        let mid_sel_nums =  vec![1, 1, 1, 0];
        let bm_multiplicities = vec![0, 1, 1, 1];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(2, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let bm_multiplicities_mle = DenseMultilinearExtension::from_evaluations_vec(2, bm_multiplicities.iter().map(|x| Fr::from(*x as u64)).collect());

        test_set_diff_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
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
            &bm_multiplicities_mle,
            &range_mle.clone(),
        )?;
        println!("passed");

        // test bad path 1: diff (l) is missing an element
        print!("SuppCheck bad path 1 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![1, 2, 3, 0]; 
        let b_sel_nums =    vec![1, 1, 1, 0];
        let l_nums =        vec![0, 4, 0, 0];
        let l_sel_nums =    vec![1, 1, 0, 0];
        let mid_nums =      vec![1, 2, 3, 0];
        let mid_sel_nums =  vec![1, 1, 1, 0];
        let bm_multiplicities = vec![1, 1, 1, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(2, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let bm_multiplicities_mle = DenseMultilinearExtension::from_evaluations_vec(2, bm_multiplicities.iter().map(|x| Fr::from(*x as u64)).collect());

        let bad_res1 = test_set_diff_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
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
            &bm_multiplicities_mle,
            &range_mle.clone(),
        );
        assert!(bad_res1.is_err());
        println!("passed");

        // test bad path 2: diff (l) has a duplicate element
        print!("SuppCheck bad path 2 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![1, 2, 3, 0]; 
        let b_sel_nums =    vec![1, 1, 1, 0];
        let l_nums =        vec![0, 4, 5, 5];
        let l_sel_nums =    vec![1, 1, 1, 1];
        let mid_nums =      vec![1, 2, 3, 0];
        let mid_sel_nums =  vec![1, 1, 1, 0];
        let bm_multiplicities = vec![1, 1, 1, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(3, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(2, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mid_mle = DenseMultilinearExtension::from_evaluations_vec(2, mid_nums.iter().map(|x| Fr::from(*x as u64)).collect());        
        let mid_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, mid_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let bm_multiplicities_mle = DenseMultilinearExtension::from_evaluations_vec(2, bm_multiplicities.iter().map(|x| Fr::from(*x as u64)).collect());

        let bad_res2 = test_set_diff_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
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
            &bm_multiplicities_mle,
            &range_mle.clone(),
        );
        assert!(bad_res2.is_err());
        println!("passed"); 

        Ok(())
    }

    fn test_set_diff_helper<F, PCS>(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a_poly: &DenseMultilinearExtension<F>,
        col_a_sel: &DenseMultilinearExtension<F>,
        col_b_poly: &DenseMultilinearExtension<F>,
        col_b_sel: &DenseMultilinearExtension<F>,
        col_l_poly: &DenseMultilinearExtension<F>,
        col_l_sel: &DenseMultilinearExtension<F>,
        col_m_poly: &DenseMultilinearExtension<F>,
        col_m_sel: &DenseMultilinearExtension<F>,
        bm_multiplicities: &DenseMultilinearExtension<F>,
        range_poly: &DenseMultilinearExtension<F>,
    ) -> Result<(), PolyIOPErrors>
    where
    PCS: PolynomialCommitmentScheme<F>,
    {
        let col_a = Col::new(prover_tracker.track_and_commit_poly(col_a_poly.clone())?, prover_tracker.track_and_commit_poly(col_a_sel.clone())?);
        let col_b = Col::new(prover_tracker.track_and_commit_poly(col_b_poly.clone())?, prover_tracker.track_and_commit_poly(col_b_sel.clone())?);
        let col_l = Col::new(prover_tracker.track_and_commit_poly(col_l_poly.clone())?, prover_tracker.track_and_commit_poly(col_l_sel.clone())?);
        let col_m = Col::new(prover_tracker.track_and_commit_poly(col_m_poly.clone())?, prover_tracker.track_and_commit_poly(col_m_sel.clone())?);
        let bm_multiplicities = prover_tracker.track_and_commit_poly(bm_multiplicities.clone())?;
        let range_col = Col::new(prover_tracker.track_and_commit_poly(range_poly.clone())?, prover_tracker.track_and_commit_poly(range_poly.clone())?);

        SetDiffIOP::<E, PCS>::prove(
            prover_tracker,
            &col_a,
            &col_b,
            &col_l,
            &col_m,
            &bm_multiplicities,
            &range_col,
        )?;
        let proof = prover_tracker.compile_proof()?;

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        let col_a_comm = ColComm::new(verifier_tracker.transfer_prover_comm(col_a.poly.id), verifier_tracker.transfer_prover_comm(col_a.selector.id), col_a.num_vars());
        let col_b_comm = ColComm::new(verifier_tracker.transfer_prover_comm(col_b.poly.id), verifier_tracker.transfer_prover_comm(col_b.selector.id), col_b.num_vars());
        let col_l_comm = ColComm::new(verifier_tracker.transfer_prover_comm(col_l.poly.id), verifier_tracker.transfer_prover_comm(col_l.selector.id), col_l.num_vars());
        let col_m_comm = ColComm::new(verifier_tracker.transfer_prover_comm(col_m.poly.id), verifier_tracker.transfer_prover_comm(col_m.selector.id), col_m.num_vars());
        let bm_multiplicities_comm = verifier_tracker.transfer_prover_comm(bm_multiplicities.id);
        let range_col_comm = ColComm::new(verifier_tracker.transfer_prover_comm(range_col.poly.id), verifier_tracker.transfer_prover_comm(range_col.selector.id), range_col.num_vars());
        SetDiffIOP::<E, PCS>::verify(
            verifier_tracker,
            &col_a_comm,
            &col_b_comm,
            &col_l_comm,
            &col_m_comm,
            &bm_multiplicities_comm,
            &range_col_comm,
        )?;
        verifier_tracker.verify_claims()?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.num_tracked_polys, v_tracker.num_tracked_polys);
        assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);

        Ok(())
    }

    #[test]
    fn set_diff_test() {
        let res = test_set_diff();
        res.unwrap();
    }
}