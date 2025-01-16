#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;

    use crate::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::One;
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        col_toolbox::set_union::set_union::SetUnionIOP,
    };

    fn test_set_union() -> Result<(), PolyIOPErrors> {
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
        let poly_a_nv = 4;
        let poly_b_nv = 4;
        let sum_nv = 5;
        let union_nv = 5;
        let poly_a_nums = (0..2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
        let poly_b_nums = poly_a_nums.iter().map(|x| x + 2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
        let mut sum_nums = poly_a_nums.clone();
        sum_nums.extend(poly_b_nums.iter().cloned());
        let union_nums = sum_nums.clone();

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let union_mle = DenseMultilinearExtension::from_evaluations_vec(union_nv, union_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let one_poly_4 = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, vec![Fr::one(); 2_usize.pow(poly_a_nv as u32)]);
        let one_poly_5 = DenseMultilinearExtension::from_evaluations_vec(sum_nv, vec![Fr::one(); 2_usize.pow((sum_nv) as u32)]);

        test_set_union_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &poly_a_mle.clone(), 
            &one_poly_4.clone(), 
            &poly_b_mle, 
            &one_poly_4.clone(), 
            &union_mle, 
            &one_poly_5.clone(),
            &range_mle.clone(),
        )?;
        println!("passed");


        // test good path 2: a and b are different sizes, some dups, non-trivial selector
        print!("SuppCheck good path 2 test: ");
        let poly_a_nv = 3;
        let poly_b_nv = 4;
        let union_nv = 4;
        let poly_a_nums = (0..2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
        let sel_a_nums = vec![1; 2_usize.pow(poly_a_nv as u32)];
        let mut poly_b_nums = vec![0; 2_usize.pow(poly_b_nv as u32)];
        poly_b_nums[0] = 2_usize.pow(poly_a_nv as u32); // 8
        let mut sel_b_nums = vec![0; 2_usize.pow(poly_b_nv as u32)];
        sel_b_nums[0] = 1;
        sel_b_nums[1] = 1;
        let mut sum_nums = poly_a_nums.clone();
        sum_nums.extend(poly_b_nums.clone());
        sum_nums.extend(vec![0; 2_usize.pow(poly_a_nv as u32)]);
        let mut sum_sel_nums = sel_a_nums.clone();
        sum_sel_nums.extend(sel_b_nums.clone());
        sum_sel_nums.extend(vec![0; 2_usize.pow(poly_a_nv as u32)]);

        let mut union_nums = Vec::<usize>::with_capacity(2_usize.pow(union_nv as u32));
        union_nums.extend(vec![0; 2_usize.pow(poly_a_nv as u32) - 1]);
        union_nums.extend(poly_a_nums.clone());
        union_nums.push(2_usize.pow(poly_a_nv as u32));
        let mut union_sel_nums = Vec::<usize>::with_capacity(2_usize.pow(union_nv as u32));
        union_sel_nums.extend(vec![0; 2_usize.pow(poly_a_nv as u32) - 1]);
        union_sel_nums.extend(sel_a_nums.clone());
        union_sel_nums.push(1);
        
        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv, sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let union_mle = DenseMultilinearExtension::from_evaluations_vec(union_nv, union_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let union_sel_mle = DenseMultilinearExtension::from_evaluations_vec(union_nv, union_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        test_set_union_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &poly_a_mle.clone(), 
            &sel_a_mle.clone(),
            &poly_b_mle, 
            &sel_b_mle.clone(),
            &union_mle, 
            &union_sel_mle.clone(),
            &range_mle.clone(),
        )?;
        println!("passed");

        // test bad path 1: but union is missing an element
        print!("SuppCheck bad path 1 test: ");
        let poly_a_nums = vec![0, 1];
        let poly_b_nums = vec![2, 3];
        let sel_a_nums = vec![1, 1];
        let sel_b_nums = vec![1, 1];
        let union_nums = vec![0, 1, 2, 0];
        let union_sel_nums = vec![1, 1, 1, 0];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(1, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(1, sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(1, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(1, sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let union_mle = DenseMultilinearExtension::from_evaluations_vec(2, union_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let union_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, union_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        let bad_res3 = test_set_union_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker.deep_copy(), 
            &mut verifier_tracker.deep_copy(), 
            &poly_a_mle.clone(), 
            &sel_a_mle.clone(),
            &poly_b_mle, 
            &sel_b_mle.clone(),
            &union_mle, 
            &union_sel_mle.clone(),
            &range_mle.clone(),
        );
        assert!(bad_res3.is_err());
        println!("passed");

        // test bad path 2: union has a duplicate element
        print!("SuppCheck bad path 2 test: ");
        let poly_a_nums = vec![0, 1];
        let poly_b_nums = vec![1, 2];
        let sel_a_nums = vec![1, 1];
        let sel_b_nums = vec![1, 1];
        let union_nums = vec![0, 1, 1, 2];
        let union_sel_nums = vec![1, 1, 1, 1];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(1, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(1, sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(1, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(1, sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let union_mle = DenseMultilinearExtension::from_evaluations_vec(2, union_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let union_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, union_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        let bad_res4 = test_set_union_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker.deep_copy(), 
            &mut verifier_tracker.deep_copy(), 
            &poly_a_mle.clone(), 
            &sel_a_mle.clone(),
            &poly_b_mle, 
            &sel_b_mle.clone(),
            &union_mle, 
            &union_sel_mle.clone(),
            &range_mle.clone(),
        );
        assert!(bad_res4.is_err());
        println!("passed"); 

        Ok(())
    }

    fn test_set_union_helper<F, PCS>(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col_a_poly: &DenseMultilinearExtension<F>,
        col_a_sel: &DenseMultilinearExtension<F>,
        col_b_poly: &DenseMultilinearExtension<F>,
        col_b_sel: &DenseMultilinearExtension<F>,
        union_col_poly: &DenseMultilinearExtension<F>,
        union_col_sel: &DenseMultilinearExtension<F>,
        range_poly: &DenseMultilinearExtension<F>,
    ) -> Result<(), PolyIOPErrors>
    where
    PCS: PolynomialCommitmentScheme<F>,
    {
        let col_a = Col::new(prover_tracker.track_and_commit_poly(col_a_poly.clone())?, prover_tracker.track_and_commit_poly(col_a_sel.clone())?);
        let col_b = Col::new(prover_tracker.track_and_commit_poly(col_b_poly.clone())?, prover_tracker.track_and_commit_poly(col_b_sel.clone())?);
        let union_col = Col::new(prover_tracker.track_and_commit_poly(union_col_poly.clone())?, prover_tracker.track_and_commit_poly(union_col_sel.clone())?);
        let range_col = Col::new(prover_tracker.track_and_commit_poly(range_poly.clone())?, prover_tracker.track_and_commit_poly(range_poly.clone())?);

        SetUnionIOP::<E, PCS>::prove(
            prover_tracker,
            &col_a,
            &col_b,
            &union_col,
            &range_col,
        )?;
        let proof = prover_tracker.compile_proof()?;

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        // let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let col_a_comm = ColComm::new(verifier_tracker.transfer_prover_comm(col_a.poly.id), verifier_tracker.transfer_prover_comm(col_a.selector.id), col_a.num_vars());
        let col_b_comm = ColComm::new(verifier_tracker.transfer_prover_comm(col_b.poly.id), verifier_tracker.transfer_prover_comm(col_b.selector.id), col_b.num_vars());
        let union_col_comm = ColComm::new(verifier_tracker.transfer_prover_comm(union_col.poly.id), verifier_tracker.transfer_prover_comm(union_col.selector.id), union_col.num_vars());
        let range_col_comm = ColComm::new(verifier_tracker.transfer_prover_comm(range_col.poly.id), verifier_tracker.transfer_prover_comm(range_col.selector.id), range_col.num_vars());
        SetUnionIOP::<E, PCS>::verify(
            verifier_tracker,
            &col_a_comm,
            &col_b_comm,
            &union_col_comm,
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
    fn set_union_test() {
        let res = test_set_union();
        res.unwrap();
    }
}