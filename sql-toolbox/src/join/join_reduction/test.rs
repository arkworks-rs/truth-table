#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::MLE;

    use crate::{
        pcs::PCS,
        PST13
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        col_toolbox::join_reduction::{
            join_reduction::JoinReductionIOP,
            utils::calc_join_reduction_lr_sel_advice,
        },
    };

    fn test_join_reduction() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let range_nums = (0..2_usize.pow(range_nv as u32)).collect::<Vec<usize>>();
        let range_mle = MLE::from_evaluations_vec(range_nv, range_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mut rng = test_rng();

        // PCS params
        let srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = PST13::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier: Verifier<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>> = Verifier::new_from_pcs_params(pcs_verifier_param);

        // Test good path 1: one-to-one join 
        print!("JoinReductionIOP good path 1 test: ");
        let nv = 3;
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![4, 5, 6, 7, 8, 0, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(nv, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(nv, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(nv, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(nv, b_sel_evals);
        let (l_sel_mle, r_sel_mle) = calc_join_reduction_lr_sel_advice::<Bls12_381>(&poly_a_mle, &a_sel_mle, &poly_b_mle, &b_sel_mle);

        test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover, 
            &mut verifier, 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        )?;
        println!("passed");

        // Test good path 2: one-to-many join 
        print!("JoinReductionIOP good path 2 test: ");
        let poly_a_nums =   vec![1, 2, 3, 0];
        let a_sel_nums =    vec![1, 1, 1, 0];
        let poly_b_nums =   vec![2, 2, 3, 3, 3, 4, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 1, 0, 0];
        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(2, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(2, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let (l_sel_mle, r_sel_mle) = calc_join_reduction_lr_sel_advice::<Bls12_381>(&poly_a_mle, &a_sel_mle, &poly_b_mle, &b_sel_mle);

        test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover, 
            &mut verifier, 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        )?;
        println!("passed");

        // Test good path 2: many-to-many join 
        print!("JoinReductionIOP good path 3 test: ");
        let poly_a_nums =   vec![1, 2, 3, 2, 3, 0, 0, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let poly_b_nums =   vec![2, 2, 3, 3, 3, 4, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 1, 0, 0];
        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(3, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(3, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let (l_sel_mle, r_sel_mle) = calc_join_reduction_lr_sel_advice::<Bls12_381>(&poly_a_mle, &a_sel_mle, &poly_b_mle, &b_sel_mle);

        test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover, 
            &mut verifier, 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        )?;
        println!("passed");

        // Test bad path 1: invalid l_sel
        print!("JoinReductionIOP bad path 1 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![4, 5, 6, 7, 8, 0, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(3, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(3, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let (mut l_sel_mle, r_sel_mle) = calc_join_reduction_lr_sel_advice::<Bls12_381>(&poly_a_mle, &a_sel_mle, &poly_b_mle, &b_sel_mle);
        let mut l_sel_evals = l_sel_mle.evaluations.clone();
        l_sel_evals[2] = Fr::from(2u64);
        l_sel_mle = MLE::from_evaluations_vec(3, l_sel_evals);

        let bad_res1 = test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        );
        assert!(bad_res1.is_err());
        println!("passed");

        // Test bad path 2: invalid r_sel
        print!("JoinReductionIOP bad path 2 test: ");
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![4, 5, 6, 7, 8, 0, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(3, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(3, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let (l_sel_mle, mut r_sel_mle) = calc_join_reduction_lr_sel_advice::<Bls12_381>(&poly_a_mle, &a_sel_mle, &poly_b_mle, &b_sel_mle);
        let mut r_sel_evals = r_sel_mle.evaluations.clone();
        r_sel_evals[2] = Fr::from(2u64);
        r_sel_mle = MLE::from_evaluations_vec(3, r_sel_evals);

        let bad_res2 = test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        );
        assert!(bad_res2.is_err());
        println!("passed");

        // Test bad path 3: l and r not disjoint
        print!("JoinReductionIOP bad path 3 test: ");
        let poly_a_nums =   vec![0, 1, 2, 3, 4, 5, 0, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 1, 0, 0];
        let poly_b_nums =   vec![4, 5, 6, 7, 8, 0, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let l_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0]; // includes 4 when it should not
        let r_sel_nums =    vec![1, 0, 1, 1, 1, 0, 0, 0]; // includes 4 when it should not 

        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let l_sel_evals = l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let r_sel_evals = r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(3, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(3, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let l_sel_mle = MLE::from_evaluations_vec(3, l_sel_evals);
        let r_sel_mle = MLE::from_evaluations_vec(3, r_sel_evals);

        let bad_res3 = test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        );
        assert!(bad_res3.is_err());
        println!("passed");

        // Test bad path 4: l missing an element
        print!("JoinReductionIOP bad path 4 test: ");
        let poly_a_nums =   vec![0, 1, 2, 3, 4, 5, 0, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 1, 0, 0];
        let poly_b_nums =   vec![4, 5, 6, 7, 8, 0, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let l_sel_nums =    vec![1, 1, 1, 0, 0, 0, 0, 0];  // zeros out 3 when it should not
        let r_sel_nums =    vec![0, 0, 1, 1, 1, 0, 0, 0];

        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let l_sel_evals = l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let r_sel_evals = r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(3, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(3, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let l_sel_mle = MLE::from_evaluations_vec(3, l_sel_evals);
        let r_sel_mle = MLE::from_evaluations_vec(3, r_sel_evals);

        let bad_res4 = test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        );
        assert!(bad_res4.is_err());
        println!("passed");

        // Test bad path 5: r missing an element
        print!("JoinReductionIOP bad path 5 test: ");
        let poly_a_nums =   vec![0, 1, 2, 3, 4, 5, 0, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 1, 0, 0];
        let poly_b_nums =   vec![4, 5, 6, 7, 8, 0, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let l_sel_nums =    vec![1, 1, 1, 1, 0, 0, 0, 0];  
        let r_sel_nums =    vec![0, 0, 0, 1, 1, 0, 0, 0]; // zeros out 6 when it should not

        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let l_sel_evals = l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let r_sel_evals = r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(3, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(3, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let l_sel_mle = MLE::from_evaluations_vec(3, l_sel_evals);
        let r_sel_mle = MLE::from_evaluations_vec(3, r_sel_evals);

        let bad_res5 = test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        );
        assert!(bad_res5.is_err());
        println!("passed");

        // Test bad path 6: l has an element in that is in mid_a and mid_b as well
        print!("JoinReductionIOP bad path 6 test: ");
        let poly_a_nums =   vec![0, 1, 2, 3, 4, 4, 5, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 1, 1, 0];
        let poly_b_nums =   vec![4, 5, 6, 7, 8, 0, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let l_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];  // included 4 when 4 should be in the middle 
        let r_sel_nums =    vec![0, 0, 1, 1, 1, 0, 0, 0];

        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let l_sel_evals = l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let r_sel_evals = r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(3, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(3, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let l_sel_mle = MLE::from_evaluations_vec(3, l_sel_evals);
        let r_sel_mle = MLE::from_evaluations_vec(3, r_sel_evals);

        let bad_res6 = test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        );
        assert!(bad_res6.is_err());
        println!("passed");

        // Test bad path 7: r has an element in that is in mid_a and mid_b as well
        print!("JoinReductionIOP bad path 7 test: ");
        let poly_a_nums =   vec![0, 1, 2, 3, 4, 5, 0, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 1, 0, 0];
        let poly_b_nums =   vec![4, 4, 5, 6, 7, 8, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 1, 0, 0];
        let l_sel_nums =    vec![1, 1, 1, 1, 0, 0, 0, 0];  
        let r_sel_nums =    vec![1, 0, 0, 1, 1, 1, 0, 0]; // includes 4 when it should not

        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let l_sel_evals = l_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let r_sel_evals = r_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = MLE::from_evaluations_vec(3, poly_a_evals);
        let a_sel_mle = MLE::from_evaluations_vec(3, a_sel_evals);
        let poly_b_mle = MLE::from_evaluations_vec(3, poly_b_evals);
        let b_sel_mle = MLE::from_evaluations_vec(3, b_sel_evals);
        let l_sel_mle = MLE::from_evaluations_vec(3, l_sel_evals);
        let r_sel_mle = MLE::from_evaluations_vec(3, r_sel_evals);

        let bad_res7 = test_join_reduction_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>>(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &range_mle.clone(),
        );
        assert!(bad_res7.is_err());
        println!("passed");
        
        Ok(())
    }

    fn test_join_reduction_helper<F, PCS>(
        prover: &mut ProverTrackerRef<F, PCS>,
        verifier: &mut Verifier<F, PCS>,
        col_a_poly: &MLE<F>,
        col_a_sel: &MLE<F>,
        col_b_poly: &MLE<F>,
        col_b_sel: &MLE<F>,
        l_sel: &MLE<F>,
        r_sel: &MLE<F>,
        range_poly: &MLE<F>,
    ) -> Result<(), PolyIOPErrors>
    where
    PCS: PCS<F>,
    {
        let col_a = Col::new(prover.track_and_commit_poly(col_a_poly.clone())?, prover.track_and_commit_poly(col_a_sel.clone())?); 
        let col_b = Col::new(prover.track_and_commit_poly(col_b_poly.clone())?, prover.track_and_commit_poly(col_b_sel.clone())?); 
        let l_sel = prover.track_and_commit_poly(l_sel.clone())?;
        let r_sel = prover.track_and_commit_poly(r_sel.clone())?;
        let range_col = Col::new(prover.track_and_commit_poly(range_poly.clone())?, prover.track_and_commit_poly(range_poly.clone())?);

        JoinReductionIOP::<E, PCS>::prove(
            prover,
            &col_a, 
            &col_b, 
            &l_sel, 
            &r_sel, 
            &range_col,
        )?;
        let proof = prover.compile_proof()?;

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier.set_proof(proof);
        let col_a_comm = ColCom::new(verifier.track_mv_com_by_id(col_a.poly.id), verifier.track_mv_com_by_id(col_a.selector.id), col_a.num_vars()); 
        let col_b_comm = ColCom::new(verifier.track_mv_com_by_id(col_b.poly.id), verifier.track_mv_com_by_id(col_b.selector.id), col_b.num_vars()); 
        let l_sel_comm = verifier.track_mv_com_by_id(l_sel.id);
        let r_sel_comm = verifier.track_mv_com_by_id(r_sel.id);
        let range_col_comm = ColCom::new(verifier.track_mv_com_by_id(range_col.poly.id), verifier.track_mv_com_by_id(range_col.selector.id), range_col.num_vars());

        JoinReductionIOP::<E, PCS>::verify(
            verifier,
            &col_a_comm,
            &col_b_comm,
            &l_sel_comm,
            &r_sel_comm,
            &range_col_comm,
        )?;
        verifier.verify()?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover.clone_underlying_tracker();
        let verifier = verifier.clone_underlying_tracker();
        assert_eq!(p_tracker.num_tracked_polys, verifier.num_tracked_polys);
        assert_eq!(p_tracker.sum_check_claims, verifier.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, verifier.zero_check_claims);

        Ok(())
    }

    #[test]
    fn join_reduction_test() {
        let res = test_join_reduction();
        res.unwrap();
    }
}