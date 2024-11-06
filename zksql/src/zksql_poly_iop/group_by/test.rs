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
    use ark_std::One;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::group_by::group_by::{AggregationType, GroupByIOP, GroupByInstructionWithProvingAdvice, GroupByInstructionWithVerifyingAdvice},
        
    };

    fn test_group_by_bad_grouping() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // create the range poly and its multiplicity vector
        let range_poly_evals = (0..2_usize.pow(range_nv as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
        let range_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, range_poly_evals);
        let range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![Fr::one(); 2_usize.pow(range_nv as u32)]);

        // set up testing basics 
        let pre_nv = 3; 
        let pre_group_nums = vec![1, 1, 1, 2, 2, 3, 0, 0];
        let pre_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let pre_agg_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let support_col_nums = vec![0, 0, 0, 0, 0, 1, 2, 3];
        let support_sel_nums = vec![0, 0, 0, 0, 0, 1, 1, 1];
        let support_mult_nums = vec![0, 0, 0, 0, 0, 3, 2, 1];
        let agg_nums = support_mult_nums.clone(); // for count its the same as support_mult_nums, this is actually a dummy var

        let pre_group_vals = pre_group_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_group_sel_vals = pre_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_agg_vals = pre_agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_col_vals = support_col_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_sel_vals = support_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_mult_vals = support_mult_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let agg_vals = agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();

        let pre_group_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_vals.clone());
        let pre_group_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_sel_vals.clone());
        let pre_agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_agg_vals.clone());
        let support_col_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_col_vals.clone());
        let support_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_sel_vals.clone());
        let support_mult_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_mult_vals.clone());
        let agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, agg_vals.clone());

        let table_vals = vec![pre_group_mle.clone(), pre_agg_mle.clone()];
        let table_sel = pre_group_sel_mle.clone();
        let grouping_cols = vec![0];
        let agg_mle_instructions = vec![(0, AggregationType::Count, agg_mle.clone())];

        // Test bad grouping 1: bad support_col_nums
        print!("GroupByIOP bad grouping 1 test: ");
        let support_col_nums = vec![0, 0, 0, 0, 0, 4, 2, 3]; // changed a 1 to a 4 here 
        let bad_support_col_vals = support_col_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let bad_support_col_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, bad_support_col_vals.clone());
        let bad_res_1 = test_group_by_helper(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &table_vals, 
            &table_sel, 
            &grouping_cols, 
            &vec![bad_support_col_mle.clone()], 
            &support_sel_mle, 
            &support_mult_mle, 
            &agg_mle_instructions, 
            &range_mle, 
            &range_sel_mle, 
            range_nv,
        );
        assert!(bad_res_1.is_err());
        println!("passed");

        // Test bad grouping 2: bad support_sel_nums
        print!("GroupByIOP bad grouping 2 test: ");
        let support_sel_nums = vec![0, 0, 0, 0, 0, 1, 1, 0]; // changes the last 1 to a 0
        let bad_support_sel_vals = support_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let bad_support_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, bad_support_sel_vals.clone());
        let bad_res_2 = test_group_by_helper(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &table_vals, 
            &table_sel, 
            &grouping_cols, 
            &vec![bad_support_sel_mle.clone()], 
            &support_sel_mle, 
            &support_mult_mle, 
            &agg_mle_instructions, 
            &range_mle, 
            &range_sel_mle, 
            range_nv,
        );
        assert!(bad_res_2.is_err());
        println!("passed");

        // Test bad grouping 3: bad support_mult_nums
        print!("GroupByIOP bad grouping 3 test: ");
        let support_mult_nums = vec![0, 0, 0, 0, 0, 3, 2, 2]; // changes the last 1 to a 2
        let bad_support_mult_vals = support_mult_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let bad_support_mult_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, bad_support_mult_vals.clone());
        let bad_res_3 = test_group_by_helper(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &table_vals, 
            &table_sel, 
            &grouping_cols, 
            &vec![bad_support_mult_mle.clone()], 
            &support_sel_mle, 
            &support_mult_mle, 
            &agg_mle_instructions, 
            &range_mle, 
            &range_sel_mle, 
            range_nv,
        );
        assert!(bad_res_3.is_err());
        println!("passed");

        Ok(())
    }

    fn test_group_by_count() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // create the range poly and its multiplicity vector
        let range_poly_evals = (0..2_usize.pow(range_nv as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
        let range_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, range_poly_evals);
        let range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![Fr::one(); 2_usize.pow(range_nv as u32)]);

        // Test the count aggregation
        let pre_nv = 3; 
        let pre_group_nums = vec![1, 1, 1, 2, 2, 3, 0, 0];
        let pre_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let pre_agg_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let support_col_nums = vec![0, 0, 0, 0, 0, 1, 2, 3]; // recall these need to be ordered for the support IOP gadget to pass
        let support_sel_nums = vec![0, 0, 0, 0, 0, 1, 1, 1];
        let support_mult_nums = vec![0, 0, 0, 0, 0, 3, 2, 1];
        let agg_nums = support_mult_nums.clone(); // for count its the same as support_mult_nums, this is actually a dummy var

        let pre_group_vals = pre_group_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_group_sel_vals = pre_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_agg_vals = pre_agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_col_vals = support_col_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_sel_vals = support_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_mult_vals = support_mult_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let agg_vals = agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();

        let pre_group_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_vals.clone());
        let pre_group_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_sel_vals.clone());
        let pre_agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_agg_vals.clone());
        let support_col_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_col_vals.clone());
        let support_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_sel_vals.clone());
        let support_mult_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_mult_vals.clone());
        let agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, agg_vals.clone());

        let table_vals = vec![pre_group_mle.clone(), pre_agg_mle.clone()];
        let table_sel = pre_group_sel_mle.clone();
        let grouping_cols = vec![0];
        let agg_mle_instructions = vec![(0, AggregationType::Count, agg_mle.clone())];
        test_group_by_helper(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &table_vals, 
            &table_sel, 
            &grouping_cols, 
            &vec![support_col_mle.clone()], 
            &support_sel_mle, 
            &support_mult_mle, 
            &agg_mle_instructions, 
            &range_mle, 
            &range_sel_mle, 
            range_nv,
        )?;
        
        Ok(())
    }

    fn test_group_by_sum() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // create the range poly and its multiplicity vector
        let range_poly_evals = (0..2_usize.pow(range_nv as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
        let range_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, range_poly_evals);
        let range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![Fr::one(); 2_usize.pow(range_nv as u32)]);

        // Test the count aggregation
        let pre_nv = 3; 
        let pre_group_nums = vec![1, 1, 1, 2, 2, 3, 0, 0];
        let pre_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let pre_agg_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let support_col_nums = vec![0, 0, 0, 0, 0, 1, 2, 3]; // recall these need to be ordered for the support IOP gadget to pass
        let support_sel_nums = vec![0, 0, 0, 0, 0, 1, 1, 1];
        let support_mult_nums = vec![0, 0, 0, 0, 0, 3, 2, 1];
        let agg_nums = vec![0, 0, 0, 0, 0, 36, 29, 16];

        let pre_group_vals = pre_group_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_group_sel_vals = pre_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_agg_vals = pre_agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_col_vals = support_col_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_sel_vals = support_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_mult_vals = support_mult_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let agg_vals = agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();

        let pre_group_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_vals.clone());
        let pre_group_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_sel_vals.clone());
        let pre_agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_agg_vals.clone());
        let support_col_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_col_vals.clone());
        let support_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_sel_vals.clone());
        let support_mult_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_mult_vals.clone());
        let agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, agg_vals.clone());

        let table_vals = vec![pre_group_mle.clone(), pre_agg_mle.clone()];
        let table_sel = pre_group_sel_mle.clone();
        let grouping_cols = vec![0];
        let agg_mle_instructions = vec![(1, AggregationType::Sum, agg_mle.clone())];

        print!("Testing group by sum good path: ");
        test_group_by_helper(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &table_vals, 
            &table_sel, 
            &grouping_cols, 
            &vec![support_col_mle.clone()], 
            &support_sel_mle, 
            &support_mult_mle, 
            &agg_mle_instructions, 
            &range_mle, 
            &range_sel_mle, 
            range_nv,
        )?;
        println!("passed");

        // Test bad path with bad agg nums
        print!("Testing group by sum bad path: ");
        let bad_agg_nums = vec![0, 0, 0, 0, 0, 16, 36, 29]; // switched nums to the wrong order
        let bad_agg_vals = bad_agg_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let bad_agg_mle = DenseMultilinearExtension::from_evaluations_vec(3, bad_agg_vals);
        let bad_agg_mle_instructions = vec![(1, AggregationType::Sum, bad_agg_mle.clone())];
        let bad_result = test_group_by_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &table_vals, 
            &table_sel, 
            &grouping_cols, 
            &vec![support_col_mle.clone()], 
            &support_sel_mle, 
            &support_mult_mle, 
            &bad_agg_mle_instructions, 
            &range_mle, 
            &range_sel_mle, 
            range_nv,
        );
        assert!(bad_result.is_err());
        println!("passed");

        Ok(())
    }

    fn test_group_by_helper<E: Pairing, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        table_vals: &Vec<DenseMultilinearExtension<E::ScalarField>>,
        table_sel: &DenseMultilinearExtension<E::ScalarField>,
        grouping_cols: &Vec<usize>,
        support_cols: &Vec<DenseMultilinearExtension<E::ScalarField>>,
        support_sel: &DenseMultilinearExtension<E::ScalarField>,
        support_mult: &DenseMultilinearExtension<E::ScalarField>,
        agg_mle_instructions: &Vec<(usize, AggregationType, DenseMultilinearExtension<E::ScalarField>)>,
        range_mle: &DenseMultilinearExtension<E::ScalarField>,
        range_sel_mle: &DenseMultilinearExtension<E::ScalarField>,
        range_nv: usize,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        let mut table_val_polys = Vec::new();
        for vals_mle in table_vals {
            let poly = prover_tracker.track_and_commit_poly(vals_mle.clone())?;
            table_val_polys.push(poly);
        }
        let table_sel_poly = prover_tracker.track_and_commit_poly(table_sel.clone())?;
        let table = Table::new(table_val_polys.clone(), table_sel_poly.clone());
        let mut support_polys = Vec::new();
        for support_mle in support_cols {
            let poly = prover_tracker.track_and_commit_poly(support_mle.clone())?;
            support_polys.push(poly);
        }
        let support_sel_poly = prover_tracker.track_and_commit_poly(support_sel.clone())?;
        let support_mult_poly = prover_tracker.track_and_commit_poly(support_mult.clone())?;
        let mut prover_agg_instructions: Vec<(usize, AggregationType, TrackedPoly<E, PCS>)> = Vec::new();
        for (col_idx, agg_type, agg_mle) in agg_mle_instructions {
            let poly = prover_tracker.track_and_commit_poly(agg_mle.clone())?;
            prover_agg_instructions.push((*col_idx, agg_type.clone(), poly));
        }
        let group_by_instructions = GroupByInstructionWithProvingAdvice {
            grouping_cols: grouping_cols.clone(),
            support_cols: support_polys.clone(),
            support_sel: support_sel_poly.clone(),
            support_multiplicity: support_mult_poly.clone(),
            agg_instr: prover_agg_instructions.clone(),
        };
        let range_poly = prover_tracker.track_and_commit_poly(range_mle.clone())?;
        let range_sel_poly = prover_tracker.track_and_commit_poly(range_sel_mle.clone())?;
        let range_bag = Bag::new(range_poly.clone(), range_sel_poly.clone());
    
        GroupByIOP::<E, PCS>::prove_with_advice(
            prover_tracker,
            &table,
            &group_by_instructions,
            &range_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;

        verifier_tracker.set_compiled_proof(proof);
        let mut table_val_comms = Vec::new();
        for vals_poly in table_val_polys {
            let comm = verifier_tracker.transfer_prover_comm(vals_poly.id);
            table_val_comms.push(comm);
        }
        let table_sel_comm = verifier_tracker.transfer_prover_comm(table_sel_poly.id);
        let table_comm = TableComm::new(table_val_comms, table_sel_comm, table.num_vars());
        let mut support_comms = Vec::new();
        for support_poly in support_polys {
            let comm = verifier_tracker.transfer_prover_comm(support_poly.id);
            support_comms.push(comm);
        }
        let support_sel_comm = verifier_tracker.transfer_prover_comm(support_sel_poly.id);
        let support_mult_comm = verifier_tracker.transfer_prover_comm(support_mult_poly.id);
        let mut verifier_agg_instructions: Vec<(usize, AggregationType, TrackedComm<E, PCS>)> = Vec::new();
        for (col_idx, agg_type, agg_poly) in prover_agg_instructions {
            let comm = verifier_tracker.transfer_prover_comm(agg_poly.id);
            verifier_agg_instructions.push((col_idx, agg_type.clone(), comm));
        }
        let group_by_instructions = GroupByInstructionWithVerifyingAdvice {
            grouping_cols: grouping_cols.clone(),
            support_cols: support_comms,
            support_sel: support_sel_comm,
            support_multiplicity: support_mult_comm,
            agg_instr: verifier_agg_instructions,
        };
        let range_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(range_poly.id), verifier_tracker.transfer_prover_comm(range_sel_poly.id), range_nv);
        GroupByIOP::<E, PCS>::verify_with_advice(
            verifier_tracker,
            &table_comm,
            &group_by_instructions,
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
    fn group_by_bad_grouping_test() {
        let res = test_group_by_bad_grouping();
        res.unwrap();
    }

    #[test]
    fn group_by_count_test() {
        let res = test_group_by_count();
        res.unwrap();
    }

    #[test]
    fn group_by_sum_test() {
        let res = test_group_by_sum();
        res.unwrap();
    }

}