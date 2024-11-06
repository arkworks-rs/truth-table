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

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::bag_inclusion::bag_inclusion::BagInclusionIOP,
    };

    // Sets up randomized inputs for testing BagInclusionIOP
    fn test_bag_inclusion_with_advice() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init g, build f and mg off of it. Test sets it to something like
        // g = [a, b, c, d, ...], f = [a, a, 0, d], mg = [2, 0, 0, 1, ...]
        let g = crate::arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let g_sel_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
        let g_sel = DenseMultilinearExtension::from_evaluations_vec(nv, g_sel_evals.clone());
        
        
        let mut f_evals = g.evaluations.clone();
        f_evals[1] = f_evals[0];
        let mut f_sel_evals = vec![Fr::one(); f_evals.len()];
        f_sel_evals[2] = Fr::zero();
        let f = DenseMultilinearExtension::from_evaluations_vec(nv, f_evals.clone());
        let f_sel = DenseMultilinearExtension::from_evaluations_vec(nv, f_sel_evals.clone());
        
        
        let mut mg_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
        mg_evals[0] = Fr::from(2u64);
        mg_evals[1] = Fr::zero();
        mg_evals[2] = Fr::zero();
        let mg = DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone());

        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // Good path 1: described above
        print!("test_bag_inclusion_with_advice_helper good path 1:");
        test_bag_inclusion_with_advice_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(),  &g.clone(), &g_sel.clone(), &mg.clone())?;
        println!("passed");

        // Good path 2: f and g are different sized
        print!("test_bag_inclusion_with_advice_helper good path 2 (f and g are different sized): ");
        let f_small_evals = [g.evaluations[0], g.evaluations[1]].to_vec();
        let f_small = DenseMultilinearExtension::from_evaluations_vec(1, f_small_evals.clone());
        let f_small_sel = DenseMultilinearExtension::from_evaluations_vec(1, vec![Fr::one(); 2_usize.pow(1 as u32)]);
        let mut mg_small_evals = vec![Fr::zero(); mg_evals.len()];
        mg_small_evals[0] = Fr::one();
        mg_small_evals[1] = Fr::one();
        let mg_small = DenseMultilinearExtension::from_evaluations_vec(nv, mg_small_evals.clone());
        test_bag_inclusion_with_advice_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f_small.clone(), &f_small_sel.clone(),  &g.clone(), &g_sel.clone(), &mg_small.clone())?;
        println!("passed");

        // bad path
        print!("test_bag_inclusion_with_advice_helper bad path 1: ");
        mg_evals[0] = Fr::one();
        let bad_mg = DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone());
        let bad_result1 = test_bag_inclusion_with_advice_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &f.clone(), &f_sel.clone(), &g.clone(), &g_sel.clone(), &bad_mg.clone());
        assert!(bad_result1.is_err());
        println!("passed");

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagInclusionIOP
    fn test_bag_inclusion_with_advice_helper<E, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        f: &DenseMultilinearExtension<E::ScalarField>,
        f_sel: &DenseMultilinearExtension<E::ScalarField>,
        g: &DenseMultilinearExtension<E::ScalarField>,
        g_sel: &DenseMultilinearExtension<E::ScalarField>,
        mg: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        let f_nv = f.num_vars;
        let g_nv = g.num_vars;
        // Set up prover_tracker and prove
        let f_bag = Bag::new(prover_tracker.track_and_commit_poly(f.clone())?, prover_tracker.track_and_commit_poly(f_sel.clone())?);
        let g_bag = Bag::new(prover_tracker.track_and_commit_poly(g.clone())?, prover_tracker.track_and_commit_poly(g_sel.clone())?);
        let mg = prover_tracker.track_and_commit_poly(mg.clone())?;

        BagInclusionIOP::<E, PCS>::prove_with_advice(
            prover_tracker,
            &f_bag,
            &g_bag,
            &mg,
        )?;
        let proof = prover_tracker.compile_proof()?;
        
        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        let f_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f_bag.poly.id), verifier_tracker.transfer_prover_comm(f_bag.selector.id), f_nv);
        let g_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(g_bag.poly.id), verifier_tracker.transfer_prover_comm(g_bag.selector.id), g_nv);
        let mg_comm = verifier_tracker.transfer_prover_comm(mg.id);
        BagInclusionIOP::<E, PCS>::verify_with_advice(
            verifier_tracker, 
            &f_bag_comm, 
            &g_bag_comm,
            &mg_comm,
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

    // Sets up randomized inputs for testing BagInclusionIOP
    fn test_bag_inclusion() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init g, build f and mg off of it. Test sets it to something like
        // g = [a, b, c, d, ...], f = [a, a, 0, d], mg = [2, 0, 0, 1, ...]
        let g = crate::arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let g_sel_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
        let g_sel = DenseMultilinearExtension::from_evaluations_vec(nv, g_sel_evals.clone());
        
        
        let mut f_evals = g.evaluations.clone();
        f_evals[1] = f_evals[0];
        let mut f_sel_evals = vec![Fr::one(); f_evals.len()];
        f_sel_evals[2] = Fr::zero();
        let f = DenseMultilinearExtension::from_evaluations_vec(nv, f_evals.clone());
        let f_sel = DenseMultilinearExtension::from_evaluations_vec(nv, f_sel_evals.clone());
        
        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // Good path 1: described above
        print!("test_bag_inclusion_helper good path 1:");
        test_bag_inclusion_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(),  &g.clone(), &g_sel.clone())?;
        println!("passed");

        // Good path 2: f and g are different sized
        print!("test_bag_inclusion_helper good path 2 (f and g are different sized): ");
        let f_small_evals = [g.evaluations[0], g.evaluations[1]].to_vec();
        let f_small = DenseMultilinearExtension::from_evaluations_vec(1, f_small_evals.clone());
        let f_small_sel = DenseMultilinearExtension::from_evaluations_vec(1, vec![Fr::one(); 2_usize.pow(1 as u32)]);
        test_bag_inclusion_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f_small.clone(), &f_small_sel.clone(),  &g.clone(), &g_sel.clone())?;
        println!("passed");

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagInclusionIOP
    fn test_bag_inclusion_helper<E, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        f: &DenseMultilinearExtension<E::ScalarField>,
        f_sel: &DenseMultilinearExtension<E::ScalarField>,
        g: &DenseMultilinearExtension<E::ScalarField>,
        g_sel: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        let f_nv = f.num_vars;
        let g_nv = g.num_vars;
        // Set up prover_tracker and prove
        let f_bag = Bag::new(prover_tracker.track_and_commit_poly(f.clone())?, prover_tracker.track_and_commit_poly(f_sel.clone())?);
        let g_bag = Bag::new(prover_tracker.track_and_commit_poly(g.clone())?, prover_tracker.track_and_commit_poly(g_sel.clone())?);

        BagInclusionIOP::<E, PCS>::prove(
            prover_tracker,
            &f_bag,
            &g_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;
        
        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        let f_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f_bag.poly.id), verifier_tracker.transfer_prover_comm(f_bag.selector.id), f_nv);
        let g_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(g_bag.poly.id), verifier_tracker.transfer_prover_comm(g_bag.selector.id), g_nv);
        BagInclusionIOP::<E, PCS>::verify(
            verifier_tracker, 
            &f_bag_comm, 
            &g_bag_comm,
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
    fn bag_inclusion_with_advice_test() {
        let res = test_bag_inclusion_with_advice();
        res.unwrap();
    }

    #[test]
    fn bag_inclusion_test() {
        let res = test_bag_inclusion();
        res.unwrap();
    }
}