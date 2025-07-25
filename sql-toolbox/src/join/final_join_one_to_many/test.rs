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
        col_toolbox::final_join_one_to_many::final_join_one_to_many::FinalJoinOneToManyIOP,
    };

    fn test_final_join_one_to_many() -> Result<(), PolyIOPErrors> {
         // testing params
         let range_nv = 10;
         let mut rng = test_rng();
 
         // PCS params
         let srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
         let (pcs_prover_param, pcs_verifier_param) = PST13::<Bls12_381>::trim(&srs, None, Some(10))?;
 
         // create trackers
         let mut prover: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
         let mut verifier: Verifier<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>> = Verifier::new_from_pcs_params(pcs_verifier_param);
 
        print!("FinalJoinOneToManyIOP good path test: ");
        let table_a_nv = 2;
        let table_b_nv = 3;

        let a_col_0_nums = vec![1, 2, 3, 4];
        let a_col_1_nums = vec![5, 6, 7, 8];
        let b_col_0_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let b_col_1_nums = vec![21, 22, 23, 24, 25, 26, 0, 0];
        let b_col_2_nums = vec![1, 1, 2, 2, 3, 3, 0, 0];
        let a_sel_nums = vec![1, 1, 1, 1];
        let b_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];

        let a_col_0_mle = MLE::from_evaluations_vec(table_a_nv, a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_col_1_mle = MLE::from_evaluations_vec(table_a_nv, a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_0_mle = MLE::from_evaluations_vec(table_b_nv, b_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_1_mle = MLE::from_evaluations_vec(table_b_nv, b_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_2_mle = MLE::from_evaluations_vec(table_b_nv, b_col_2_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = MLE::from_evaluations_vec(table_a_nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = MLE::from_evaluations_vec(table_b_nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        
        let a_cols = vec![a_col_0_mle.clone(), a_col_1_mle.clone()];
        let b_cols = vec![b_col_0_mle.clone(), b_col_1_mle.clone(), b_col_2_mle.clone()];
        let a_join_col_index = 0;
        let b_join_col_index = 2;

        test_final_join_one_to_many_helper(
            &mut prover, 
            &mut verifier, 
            &a_cols, 
            &b_cols, 
            &a_sel_mle, 
            &b_sel_mle, 
            a_join_col_index,
            b_join_col_index,
        )?;
        println!("passed");


         Ok(())
    }

    fn test_final_join_one_to_many_helper<F, PCS>(
        prover: &mut ProverTrackerRef<F, PCS>,
        verifier: &mut Verifier<F, PCS>,
        table_a_cols: &Vec::<MLE<F>>,
        table_b_cols: &Vec::<MLE<F>>,
        table_a_sel: &MLE<F>,
        table_b_sel: &MLE<F>,
        a_join_col_index: usize,
        b_join_col_index: usize,
    ) -> Result<(), PolyIOPErrors>
    where
    PCS: PCS<F>,
    {
        let mut table_a_col_polys = Vec::<TrackedPoly<F, PCS>>::new();
        for col in table_a_cols {
            let col_poly = prover.track_and_commit_poly(col.clone())?;
            table_a_col_polys.push(col_poly);
        }
        let table_a_sel_poly = prover.track_and_commit_poly(table_a_sel.clone())?;
        let table_a = Table::new(table_a_col_polys.clone(), table_a_sel_poly.clone());
        let mut table_b_col_polys = Vec::<TrackedPoly<F, PCS>>::new();
        for col in table_b_cols {
            let col_poly = prover.track_and_commit_poly(col.clone())?;
            table_b_col_polys.push(col_poly);
        }
        let table_b_sel_poly = prover.track_and_commit_poly(table_b_sel.clone())?;
        let table_b = Table::new(table_b_col_polys.clone(), table_b_sel_poly.clone());

        let res_table = FinalJoinOneToManyIOP::<E, PCS>::prove(
            prover,
            &table_a,
            &table_b,
            a_join_col_index,
            b_join_col_index,
        )?;
        let proof = prover.compile_proof()?;
        assert_eq!(res_table.col_vals.len(), table_a.col_vals.len() + table_b.col_vals.len());
        for i in table_a.col_vals.len()..res_table.col_vals.len() {
            assert_eq!(res_table.col_vals[i].id, table_b.col_vals[i - table_a.col_vals.len()].id);
        }
        assert_eq!(res_table.selector.id, table_b.selector.id);

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier.set_proof(proof);
        let mut table_a_col_comms = Vec::<TrackedOracle<F, PCS>>::new();
        for poly in table_a_col_polys {
            let id = poly.id;
            let comm = verifier.track_mv_com_by_id(id);
            table_a_col_comms.push(comm);
        }
        let table_a_sel_comm = verifier.track_mv_com_by_id(table_a_sel_poly.id);
        let table_a_comm = TableComm::new(table_a_col_comms, table_a_sel_comm, table_a.num_vars());
        let mut table_b_col_comms = Vec::<TrackedOracle<F, PCS>>::new();
        for poly in table_b_col_polys {
            let id = poly.id;
            let comm = verifier.track_mv_com_by_id(id);
            table_b_col_comms.push(comm);
        }
        let table_b_sel_comm = verifier.track_mv_com_by_id(table_b_sel_poly.id);
        let table_b_comm = TableComm::new(table_b_col_comms, table_b_sel_comm, table_b.num_vars());

        FinalJoinOneToManyIOP::<E, PCS>::verify(
            verifier,
            &table_a_comm,
            &table_b_comm,
            a_join_col_index,
            b_join_col_index,
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

    fn test_final_join_one_to_many_with_advice() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let mut rng = test_rng();

        // PCS params
        let srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = PST13::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier: Verifier<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>> = Verifier::new_from_pcs_params(pcs_verifier_param);

        // // Test good path 1: one-to-one join simple case
        print!("FinalJoinOneToManyIOP good path 1 test: ");
        let table_a_nv = 2;
        let table_b_nv = 2;

        let a_col_0_nums = vec![1, 2, 3, 4];
        let a_col_1_nums = vec![5, 6, 7, 8];
        let b_col_0_nums = vec![1, 2, 3, 4];
        let b_col_1_nums = vec![15, 16, 17, 18];
        let a_sel_nums = vec![1, 1, 1, 1];
        let b_sel_nums = vec![1, 1, 1, 1];
        
        let a_col_0_mle = MLE::from_evaluations_vec(table_a_nv, a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_col_1_mle = MLE::from_evaluations_vec(table_a_nv, a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_0_mle = MLE::from_evaluations_vec(table_b_nv, b_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_1_mle = MLE::from_evaluations_vec(table_b_nv, b_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = MLE::from_evaluations_vec(table_a_nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = MLE::from_evaluations_vec(table_b_nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        
        let a_cols = vec![a_col_0_mle.clone(), a_col_1_mle.clone()];
        let b_cols = vec![b_col_0_mle.clone(), b_col_1_mle.clone()];
        let a_join_col_index = 0;
        let b_join_col_index = 0;
        let transformed_a_cols = vec![a_col_0_mle.clone(), a_col_1_mle.clone()];

        test_final_join_one_to_many_with_advice_helper(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &a_cols, 
            &b_cols, 
            &a_sel_mle, 
            &b_sel_mle, 
            a_join_col_index,
            b_join_col_index,
            &transformed_a_cols,
        )?;
        println!("passed");

        // Test good path 2: one-to-many join complex case 
        print!("FinalJoinOneToManyIOP good path 2 test: ");
        let table_a_nv = 2;
        let table_b_nv = 3;

        let a_col_0_nums = vec![1, 2, 3, 4];
        let a_col_1_nums = vec![5, 6, 7, 8];
        let b_col_0_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let b_col_1_nums = vec![21, 22, 23, 24, 25, 26, 0, 0];
        let b_col_2_nums = vec![1, 1, 2, 2, 3, 3, 0, 0];
        let a_sel_nums = vec![1, 1, 1, 1];
        let b_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let trans_a_col_0_nums = vec![1, 1, 2, 2, 3, 3, 0, 0];
        let trans_a_col_1_nums = vec![5, 5, 6, 6, 7, 7, 0, 0];

        let a_col_0_mle = MLE::from_evaluations_vec(table_a_nv, a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_col_1_mle = MLE::from_evaluations_vec(table_a_nv, a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_0_mle = MLE::from_evaluations_vec(table_b_nv, b_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_1_mle = MLE::from_evaluations_vec(table_b_nv, b_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_2_mle = MLE::from_evaluations_vec(table_b_nv, b_col_2_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = MLE::from_evaluations_vec(table_a_nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = MLE::from_evaluations_vec(table_b_nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let trans_a_col_0_mle = MLE::from_evaluations_vec(table_b_nv, trans_a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let trans_a_col_1_mle = MLE::from_evaluations_vec(table_b_nv, trans_a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        
        let a_cols = vec![a_col_0_mle.clone(), a_col_1_mle.clone()];
        let b_cols = vec![b_col_0_mle.clone(), b_col_1_mle.clone(), b_col_2_mle.clone()];
        let a_join_col_index = 0;
        let b_join_col_index = 2;
        let transformed_a_cols = vec![trans_a_col_0_mle.clone(), trans_a_col_1_mle.clone()];

        test_final_join_one_to_many_with_advice_helper(
            &mut prover, 
            &mut verifier, 
            &a_cols, 
            &b_cols, 
            &a_sel_mle, 
            &b_sel_mle, 
            a_join_col_index,
            b_join_col_index,
            &transformed_a_cols,
        )?;
        println!("passed");

        // Test bad path 1: join columns aren't equal
        print!("FinalJoinOneToManyIOP bad path 1 test: ");
        let table_a_nv = 2;
        let table_b_nv = 3;

        let a_col_0_nums = vec![1, 2, 3, 4];
        let a_col_1_nums = vec![5, 6, 7, 8];
        let b_col_0_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let b_col_1_nums = vec![21, 22, 23, 24, 25, 26, 0, 0];
        let b_col_2_nums = vec![1, 1, 2, 2, 3, 3, 0, 0];
        let a_sel_nums = vec![1, 1, 1, 1];
        let b_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let trans_a_col_0_nums = vec![2, 2, 1, 1, 3, 3, 0, 0];
        let trans_a_col_1_nums = vec![6, 6, 5, 5, 7, 7, 0, 0];

        let a_col_0_mle = MLE::from_evaluations_vec(table_a_nv, a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_col_1_mle = MLE::from_evaluations_vec(table_a_nv, a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_0_mle = MLE::from_evaluations_vec(table_b_nv, b_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_1_mle = MLE::from_evaluations_vec(table_b_nv, b_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_2_mle = MLE::from_evaluations_vec(table_b_nv, b_col_2_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = MLE::from_evaluations_vec(table_a_nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = MLE::from_evaluations_vec(table_b_nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let trans_a_col_0_mle = MLE::from_evaluations_vec(table_b_nv, trans_a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let trans_a_col_1_mle = MLE::from_evaluations_vec(table_b_nv, trans_a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        
        let a_cols = vec![a_col_0_mle.clone(), a_col_1_mle.clone()];
        let b_cols = vec![b_col_0_mle.clone(), b_col_1_mle.clone(), b_col_2_mle.clone()];
        let a_join_col_index = 0;
        let b_join_col_index = 2;
        let transformed_a_cols = vec![trans_a_col_0_mle.clone(), trans_a_col_1_mle.clone()];

        let bad_result1 = test_final_join_one_to_many_with_advice_helper(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &a_cols, 
            &b_cols, 
            &a_sel_mle, 
            &b_sel_mle, 
            a_join_col_index,
            b_join_col_index,
            &transformed_a_cols,
        );
        assert!(bad_result1.is_err());
        println!("passed");

        // test bad path 2: transformed a cols add in elements that are not in table_a
        print!("FinalJoinOneToManyIOP bad path 2 test: ");
        let table_a_nv = 2;
        let table_b_nv = 3;

        let a_col_0_nums = vec![0, 2, 3, 4]; // 1 was removed from table_a here 
        let a_col_1_nums = vec![0, 6, 7, 8];
        let b_col_0_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let b_col_1_nums = vec![21, 22, 23, 24, 25, 26, 0, 0];
        let b_col_2_nums = vec![1, 1, 2, 2, 3, 3, 0, 0];
        let a_sel_nums = vec![0, 1, 1, 1];
        let b_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let trans_a_col_0_nums = vec![1, 1, 2, 2, 3, 3, 0, 0];
        let trans_a_col_1_nums = vec![5, 5, 6, 6, 7, 7, 0, 0];

        let a_col_0_mle = MLE::from_evaluations_vec(table_a_nv, a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_col_1_mle = MLE::from_evaluations_vec(table_a_nv, a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_0_mle = MLE::from_evaluations_vec(table_b_nv, b_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_1_mle = MLE::from_evaluations_vec(table_b_nv, b_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_2_mle = MLE::from_evaluations_vec(table_b_nv, b_col_2_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = MLE::from_evaluations_vec(table_a_nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = MLE::from_evaluations_vec(table_b_nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let trans_a_col_0_mle = MLE::from_evaluations_vec(table_b_nv, trans_a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let trans_a_col_1_mle = MLE::from_evaluations_vec(table_b_nv, trans_a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        
        let a_cols = vec![a_col_0_mle.clone(), a_col_1_mle.clone()];
        let b_cols = vec![b_col_0_mle.clone(), b_col_1_mle.clone(), b_col_2_mle.clone()];
        let a_join_col_index = 0;
        let b_join_col_index = 2;
        let transformed_a_cols = vec![trans_a_col_0_mle.clone(), trans_a_col_1_mle.clone()];

        let bad_result2 = test_final_join_one_to_many_with_advice_helper(
            &mut prover.deep_copy(), 
            &mut verifier.deep_copy(), 
            &a_cols, 
            &b_cols, 
            &a_sel_mle, 
            &b_sel_mle, 
            a_join_col_index,
            b_join_col_index,
            &transformed_a_cols,
        );
        assert!(bad_result2.is_err());
        println!("passed");

        // Test bad path 3: join index is wrong
        print!("FinalJoinOneToManyIOP bad path 3 test: ");
        let table_a_nv = 2;
        let table_b_nv = 3;

        let a_col_0_nums = vec![1, 2, 3, 4];
        let a_col_1_nums = vec![5, 6, 7, 8];
        let b_col_0_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let b_col_1_nums = vec![21, 22, 23, 24, 25, 26, 0, 0];
        let b_col_2_nums = vec![1, 1, 2, 2, 3, 3, 0, 0];
        let a_sel_nums = vec![1, 1, 1, 1];
        let b_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let trans_a_col_0_nums = vec![1, 1, 2, 2, 3, 3, 0, 0];
        let trans_a_col_1_nums = vec![5, 5, 6, 6, 7, 7, 0, 0];

        let a_col_0_mle = MLE::from_evaluations_vec(table_a_nv, a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_col_1_mle = MLE::from_evaluations_vec(table_a_nv, a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_0_mle = MLE::from_evaluations_vec(table_b_nv, b_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_1_mle = MLE::from_evaluations_vec(table_b_nv, b_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_col_2_mle = MLE::from_evaluations_vec(table_b_nv, b_col_2_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = MLE::from_evaluations_vec(table_a_nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = MLE::from_evaluations_vec(table_b_nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let trans_a_col_0_mle = MLE::from_evaluations_vec(table_b_nv, trans_a_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let trans_a_col_1_mle = MLE::from_evaluations_vec(table_b_nv, trans_a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        
        let a_cols = vec![a_col_0_mle.clone(), a_col_1_mle.clone()];
        let b_cols = vec![b_col_0_mle.clone(), b_col_1_mle.clone(), b_col_2_mle.clone()];
        let a_join_col_index = 0;
        let b_join_col_index = 0;
        let transformed_a_cols = vec![trans_a_col_0_mle.clone(), trans_a_col_1_mle.clone()];

        let bad_result3 = test_final_join_one_to_many_with_advice_helper(
            &mut prover, 
            &mut verifier, 
            &a_cols, 
            &b_cols, 
            &a_sel_mle, 
            &b_sel_mle, 
            a_join_col_index,
            b_join_col_index,
            &transformed_a_cols,
        );
        assert!(bad_result3.is_err());
        println!("passed");


        Ok(())
    }
    fn test_final_join_one_to_many_with_advice_helper<F, PCS>(
        prover: &mut ProverTrackerRef<F, PCS>,
        verifier: &mut Verifier<F, PCS>,
        table_a_cols: &Vec::<MLE<F>>,
        table_b_cols: &Vec::<MLE<F>>,
        table_a_sel: &MLE<F>,
        table_b_sel: &MLE<F>,
        a_join_col_index: usize,
        b_join_col_index: usize,
        transformed_a_cols: &Vec::<MLE<F>>,
    ) -> Result<(), PolyIOPErrors>
    where
    PCS: PCS<F>,
    {
        let mut table_a_col_polys = Vec::<TrackedPoly<F, PCS>>::new();
        for col in table_a_cols {
            let col_poly = prover.track_and_commit_poly(col.clone())?;
            table_a_col_polys.push(col_poly);
        }
        let table_a_sel_poly = prover.track_and_commit_poly(table_a_sel.clone())?;
        let table_a = Table::new(table_a_col_polys.clone(), table_a_sel_poly.clone());
        let mut table_b_col_polys = Vec::<TrackedPoly<F, PCS>>::new();
        for col in table_b_cols {
            let col_poly = prover.track_and_commit_poly(col.clone())?;
            table_b_col_polys.push(col_poly);
        }
        let table_b_sel_poly = prover.track_and_commit_poly(table_b_sel.clone())?;
        let table_b = Table::new(table_b_col_polys.clone(), table_b_sel_poly.clone());
        let mut transformed_a_col_polys = Vec::<TrackedPoly<F, PCS>>::new();
        for col in transformed_a_cols {
            let col_poly = prover.track_and_commit_poly(col.clone())?;
            transformed_a_col_polys.push(col_poly);
        }

        let res_table = FinalJoinOneToManyIOP::<E, PCS>::prove_with_advice(
            prover,
            &table_a,
            &table_b,
            a_join_col_index,
            b_join_col_index,
            &transformed_a_col_polys,
        )?;
        let proof = prover.compile_proof()?;
        assert_eq!(res_table.col_vals.len(), table_a.col_vals.len() + table_b.col_vals.len());
        for i in table_a.col_vals.len()..res_table.col_vals.len() {
            assert_eq!(res_table.col_vals[i].id, table_b.col_vals[i - table_a.col_vals.len()].id);
        }
        assert_eq!(res_table.selector.id, table_b.selector.id);

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier.set_proof(proof);
        let mut table_a_col_comms = Vec::<TrackedOracle<F, PCS>>::new();
        for poly in table_a_col_polys {
            let id = poly.id;
            let comm = verifier.track_mv_com_by_id(id);
            table_a_col_comms.push(comm);
        }
        let table_a_sel_comm = verifier.track_mv_com_by_id(table_a_sel_poly.id);
        let table_a_comm = TableComm::new(table_a_col_comms, table_a_sel_comm, table_a.num_vars());
        let mut table_b_col_comms = Vec::<TrackedOracle<F, PCS>>::new();
        for poly in table_b_col_polys {
            let id = poly.id;
            let comm = verifier.track_mv_com_by_id(id);
            table_b_col_comms.push(comm);
        }
        let table_b_sel_comm = verifier.track_mv_com_by_id(table_b_sel_poly.id);
        let table_b_comm = TableComm::new(table_b_col_comms, table_b_sel_comm, table_b.num_vars());
        let mut transformed_a_col_comms = Vec::<TrackedOracle<F, PCS>>::new();
        for poly in transformed_a_col_polys {
            let id = poly.id;
            let comm = verifier.track_mv_com_by_id(id);
            transformed_a_col_comms.push(comm);
        }

        FinalJoinOneToManyIOP::<E, PCS>::verify_with_advice(
            verifier,
            &table_a_comm,
            &table_b_comm,
            a_join_col_index,
            b_join_col_index,
            &transformed_a_col_comms,
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
    fn final_join_one_to_many_test() {
        let res = test_final_join_one_to_many();
        res.unwrap();
    }

    #[test]
    fn final_join_one_to_many_with_advice_test() {
        let res = test_final_join_one_to_many_with_advice();
        res.unwrap();
    }
}