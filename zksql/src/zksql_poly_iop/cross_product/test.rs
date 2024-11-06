#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::MultilinearExtension;
    use ark_poly::DenseMultilinearExtension;
    use ark_std::One;
    use ark_std::Zero;

    use rand_chacha::rand_core::le;
    use crate::subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::cross_product::cross_product::CrossProductIOP,
    };

    fn test_cross_product() -> Result<(), PolyIOPErrors> {
        // testing params
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, 10)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // good path 1: table_in = table_out
        let a_col_1_nums = vec![1, 2, 3, 0];
        let a_col_2_nums = vec![4, 5, 6, 0];
        let a_col_3_nums = vec![7, 8, 9, 0];
        let a_sel_nums = vec![1, 1, 1, 0];
        let b_col_1_nums = vec![20, 21, 22, 23, 24, 25, 0, 0];
        let b_col_2_nums = vec![30, 31, 32, 33, 34, 35, 0, 0];
        let b_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];

        let a_col_1_evals = a_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let a_col_2_evals = a_col_2_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let a_col_3_evals = a_col_3_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let b_col_1_evals = b_col_1_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let b_col_2_evals = b_col_2_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect();

        let a_col_1_mle = DenseMultilinearExtension::from_evaluations_vec(2, a_col_1_evals);
        let a_col_2_mle = DenseMultilinearExtension::from_evaluations_vec(2, a_col_2_evals);
        let a_col_3_mle = DenseMultilinearExtension::from_evaluations_vec(2, a_col_3_evals);
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(2, a_sel_evals);
        let b_col_1_mle = DenseMultilinearExtension::from_evaluations_vec(3, b_col_1_evals);
        let b_col_2_mle = DenseMultilinearExtension::from_evaluations_vec(3, b_col_2_evals);
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, b_sel_evals);

        // do proving stuff 
        let a_col_1 = prover_tracker.track_and_commit_poly(a_col_1_mle.clone())?;
        let a_col_2 = prover_tracker.track_and_commit_poly(a_col_2_mle.clone())?;
        let a_col_3 = prover_tracker.track_and_commit_poly(a_col_3_mle.clone())?;
        let a_cols = vec![a_col_1, a_col_2, a_col_3];
        let a_sel = prover_tracker.track_and_commit_poly(a_sel_mle.clone())?;
        let a_table = Table::new(a_cols, a_sel);

        let b_col_1 = prover_tracker.track_and_commit_poly(b_col_1_mle.clone())?;
        let b_col_2 = prover_tracker.track_and_commit_poly(b_col_2_mle.clone())?;
        let b_cols = vec![b_col_1, b_col_2];
        let b_sel = prover_tracker.track_and_commit_poly(b_sel_mle.clone())?;
        let b_table = Table::new(b_cols, b_sel);
        

        let cross_table = CrossProductIOP::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::prover_cross_product(
            &a_table.clone(), 
            &b_table.clone(),
        )?;

        // check an a_col, a b_col, and the selector are correct for the prover
        let exp_cross_table_col_0_nums = [1, 1, 1, 1, 1, 1, 1, 1,
                                                     2, 2, 2, 2, 2, 2, 2, 2,
                                                     3, 3, 3, 3, 3, 3, 3, 3,
                                                     0, 0, 0, 0, 0, 0, 0, 0, 
                                                     ];
        let exp_cross_table_col_3_nums = [20, 21, 22, 23, 24, 25, 0, 0,
                                                     20, 21, 22, 23, 24, 25, 0, 0,
                                                     20, 21, 22, 23, 24, 25, 0, 0,
                                                     20, 21, 22, 23, 24, 25, 0, 0,
                                                     ];
        let exp_cross_table_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0,
                                                      1, 1, 1, 1, 1, 1, 0, 0,
                                                      1, 1, 1, 1, 1, 1, 0, 0,
                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                     ];
        let exp_cross_table_col_0_evals = exp_cross_table_col_0_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_cross_table_col_3_evals = exp_cross_table_col_3_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_cross_table_sel_evals = exp_cross_table_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        assert_eq!(exp_cross_table_col_0_evals, cross_table.col_vals[0].evaluations());
        assert_eq!(exp_cross_table_col_3_evals, cross_table.col_vals[3].evaluations());
        assert_eq!(exp_cross_table_sel_evals, cross_table.selector.evaluations());

        // check the same for the verifier
        let col_0_sum = cross_table.col_vals[0].evaluations().iter().sum::<Fr>();
        let col_3_sum = cross_table.col_vals[3].evaluations().iter().sum::<Fr>();
        let sel_sum = cross_table.selector.evaluations().iter().sum::<Fr>();
        prover_tracker.add_sumcheck_claim(cross_table.col_vals[0].id, col_0_sum);
        prover_tracker.add_sumcheck_claim(cross_table.col_vals[3].id, col_3_sum);
        prover_tracker.add_sumcheck_claim(cross_table.selector.id, sel_sum);
        let proof = prover_tracker.compile_proof()?;

        verifier_tracker.set_compiled_proof(proof);
        let a_col_1_comm = verifier_tracker.transfer_prover_comm(a_table.col_vals[0].id);
        let a_col_2_comm = verifier_tracker.transfer_prover_comm(a_table.col_vals[1].id);
        let a_col_3_comm = verifier_tracker.transfer_prover_comm(a_table.col_vals[2].id);
        let a_cols_comm = vec![a_col_1_comm, a_col_2_comm, a_col_3_comm];
        let a_sel_comm = verifier_tracker.transfer_prover_comm(a_table.selector.id);
        let a_table_comm = TableComm::new(a_cols_comm, a_sel_comm, a_table.num_vars());

        let b_col_1_comm = verifier_tracker.transfer_prover_comm(b_table.col_vals[0].id);
        let b_col_2_comm = verifier_tracker.transfer_prover_comm(b_table.col_vals[1].id);
        let b_cols_comm = vec![b_col_1_comm, b_col_2_comm];
        let b_sel_comm = verifier_tracker.transfer_prover_comm(b_table.selector.id);
        let b_table_comm = TableComm::new(b_cols_comm, b_sel_comm, b_table.num_vars());

        CrossProductIOP::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::verifier_cross_product(
            &a_table_comm,
            &b_table_comm,
        )?;
        verifier_tracker.add_sumcheck_claim(cross_table.col_vals[0].id, col_0_sum);
        verifier_tracker.add_sumcheck_claim(cross_table.col_vals[3].id, col_3_sum);
        verifier_tracker.add_sumcheck_claim(cross_table.selector.id, sel_sum);
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
    fn cross_product_test() {
        let res = test_cross_product();
        res.unwrap();
    }
}