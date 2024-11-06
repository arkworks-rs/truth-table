


#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;
    use ark_std::{Zero, One};
    use crate::subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;
    use ark_std::rand::prelude::SliceRandom;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::bag_presc_perm::bag_presc_perm::BagPrescPermIOP,
    };

    // Sets up randomized inputs for testing BagPrescPermIOP
    fn test_bag_presc_perm() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // randomly init f, and a permuation vec, and build g off of it
        let one_poly = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]);
        let f = crate::arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let f_evals: Vec<Fr> = f.evaluations.clone();
        let mut permute_vec: Vec<usize> = (0..f_evals.len()).collect();
        permute_vec.shuffle(&mut rng);
        let perm_evals: Vec<Fr> = permute_vec.iter().map(|x| Fr::from(*x as u64)).collect();
        let perm = DenseMultilinearExtension::from_evaluations_vec(nv, perm_evals.clone());
        let g_evals: Vec<Fr> = permute_vec.iter().map(|&i| f_evals[i]).collect();
        let g = DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone());
        let f_sel = one_poly.clone();
        let g_sel = one_poly.clone();

        // good path
        test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(), &g.clone(), &g_sel.clone(), &perm.clone())?;
        println!("test_presc_perm good path 1 passed");

        // bad path 1 - different elements
        let mut bad_f_evals = f_evals.clone();
        bad_f_evals[0] = Fr::one();
        bad_f_evals[1] = Fr::one();
        let bad_f = DenseMultilinearExtension::from_evaluations_vec(nv, bad_f_evals.clone());
        let bad_f_sel = one_poly.clone();
        let bad_result1 = test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &bad_f.clone(), &bad_f_sel.clone(), &g.clone(), &g_sel.clone(), &perm.clone());
        assert!(bad_result1.is_err());
        println!("test_presc_perm bad path 1 passed");

        // bad path 2 - f and g are a different permutation than perm
        let mut bad_perm_evals = perm_evals.clone();
        let old_0_eval = perm_evals[0];
        bad_perm_evals[0] = bad_perm_evals[1];
        bad_perm_evals[1] = old_0_eval;
        let bad_perm = DenseMultilinearExtension::from_evaluations_vec(nv, bad_perm_evals.clone());
        let bad_result2 = test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &f.clone(), &f_sel.clone(), &g.clone(), &g_sel.clone(), &bad_perm.clone());
        assert!(bad_result2.is_err());
        println!("test_presc_perm bad path 2 passed");

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagPrescPermIOP
    fn test_bag_presc_perm_helper<E, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        f: &DenseMultilinearExtension<E::ScalarField>,
        f_sel: &DenseMultilinearExtension<E::ScalarField>,
        g: &DenseMultilinearExtension<E::ScalarField>,
        g_sel: &DenseMultilinearExtension<E::ScalarField>,
        perm: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        let nv = f.num_vars;
        // Set up prover_tracker and prove
        let f_bag = Bag::new(prover_tracker.track_and_commit_poly(f.clone())?, prover_tracker.track_and_commit_poly(f_sel.clone())?);
        let g_bag = Bag::new(prover_tracker.track_and_commit_poly(g.clone())?, prover_tracker.track_and_commit_poly(g_sel.clone())?);
        let perm = prover_tracker.track_and_commit_poly(perm.clone())?;
        
        BagPrescPermIOP::<E, PCS>::prove(
            prover_tracker,
            &f_bag,
            &g_bag,
            &perm,
        )?;
        let proof = prover_tracker.compile_proof()?;

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        let f_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f_bag.poly.id), verifier_tracker.transfer_prover_comm(f_bag.selector.id), nv);
        let g_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(g_bag.poly.id), verifier_tracker.transfer_prover_comm(g_bag.selector.id), nv);
        let perm_comm = verifier_tracker.transfer_prover_comm(perm.id);
        BagPrescPermIOP::<E, PCS>::verify(verifier_tracker, &f_bag_comm, &g_bag_comm, &perm_comm)?;
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
    fn bag_presc_perm_test() {
        let res = test_bag_presc_perm();
        res.unwrap();
    }
}

