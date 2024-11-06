
#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;
    use ark_std::One;
    use crate::subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::bag_eq::bag_eq::BagEqIOP,
    };
    

    // Sets up randomized inputs for testing BagEqCheck
    fn test_bageq() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init f, mf, and a permutation vec, and build g, mg based off of it
        let f = crate::arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let g = crate::arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let one_poly = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]);
        let f_sel = one_poly.clone();
        let g_sel = one_poly.clone();
        
        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // Good Path 
        test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(),  &g.clone(), &g_sel.clone())?;
        println!("Good path passed");

        // Bad path
        let mut h_evals = f.evaluations.clone();
        h_evals[0] = h_evals[0] + Fr::one();
        let h = DenseMultilinearExtension::from_evaluations_vec(f.num_vars, h_evals);
        let h_sel = one_poly.clone();

        let bad_result1 = test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &f.clone(), &f_sel.clone(), &h.clone(), &h_sel.clone());
        assert!(bad_result1.is_err());
        println!("Bad path passed");

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagEqCheck
    fn test_bageq_helper<E, PCS>(
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


        BagEqIOP::<E, PCS>::prove(
            prover_tracker,
            &f_bag,
            &g_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;
        
        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        let f_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f_bag.poly.id), verifier_tracker.transfer_prover_comm(f_bag.selector.id), f_nv);
        let g_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(g_bag.poly.id), verifier_tracker.transfer_prover_comm(g_bag.selector.id), g_nv);
        BagEqIOP::<E, PCS>::verify(verifier_tracker, &f_bag_comm, &g_bag_comm)?;
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
    fn bageq_test() {
        let res = test_bageq();
        res.unwrap();
    }
}
