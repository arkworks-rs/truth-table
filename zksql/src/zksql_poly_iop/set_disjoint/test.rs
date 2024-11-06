#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;

    use crate::subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::One;
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::set_disjoint::set_disjoint::SetDisjointIOP,
    };

    fn test_set_disjoint() -> Result<(), PolyIOPErrors> {
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

        // Test good path 1: a and b are same size, are disjoint
        print!("BagSuppIOP good path 1 test: ");
        let poly_a_nv = 4;
        let poly_b_nv = 4;
        let poly_a_nums = (0..2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
        let poly_b_nums = poly_a_nums.iter().map(|x| x + 2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let one_poly_4 = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, vec![Fr::one(); 2_usize.pow(poly_a_nv as u32)]);

        test_set_disjoint_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &poly_a_mle.clone(), 
            &one_poly_4.clone(), 
            &poly_b_mle, 
            &one_poly_4.clone(), 
            &range_mle.clone(),
        )?;
        println!("passed");


        // test good path 2: a and b are different sizes, non-trivial selector
        print!("BagSuppIOP good path 2 test: ");
        let poly_a_nv = 3;
        let poly_b_nv = 2;
        let poly_a_nums = (0..2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
        let sel_a_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let poly_b_nums = [10, 11, 12, 0];
        let sel_b_nums = [1, 1, 1, 0];
        
        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv, sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        test_set_disjoint_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &poly_a_mle.clone(), 
            &sel_a_mle.clone(),
            &poly_b_mle, 
            &sel_b_mle.clone(),
            &range_mle.clone(),
        )?;
        println!("passed");

        // test bad path 1: there is a shared element
        print!("BagSuppIOP bad path 1 test: ");
        let poly_a_nums = vec![0, 1];
        let poly_b_nums = vec![1, 2];
        let sel_a_nums = vec![1, 1];
        let sel_b_nums = vec![1, 1];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(1, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(1, sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(1, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(1, sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());

        let bad_res = test_set_disjoint_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker.deep_copy(), 
            &mut verifier_tracker.deep_copy(), 
            &poly_a_mle.clone(), 
            &sel_a_mle.clone(),
            &poly_b_mle, 
            &sel_b_mle.clone(),
            &range_mle.clone(),
        );
        assert!(bad_res.is_err());
        println!("passed"); 

        Ok(())
    }

    fn test_set_disjoint_helper<E: Pairing, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_a_sel: &DenseMultilinearExtension<E::ScalarField>,
        bag_b_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_b_sel: &DenseMultilinearExtension<E::ScalarField>,
        range_poly: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        let bag_a = Bag::new(prover_tracker.track_and_commit_poly(bag_a_poly.clone())?, prover_tracker.track_and_commit_poly(bag_a_sel.clone())?);
        let bag_b = Bag::new(prover_tracker.track_and_commit_poly(bag_b_poly.clone())?, prover_tracker.track_and_commit_poly(bag_b_sel.clone())?);
        let range_bag = Bag::new(prover_tracker.track_and_commit_poly(range_poly.clone())?, prover_tracker.track_and_commit_poly(range_poly.clone())?);

        SetDisjointIOP::<E, PCS>::prove(
            prover_tracker,
            &bag_a,
            &bag_b,
            &range_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        // let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let bag_a_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_a.poly.id), verifier_tracker.transfer_prover_comm(bag_a.selector.id), bag_a.num_vars());
        let bag_b_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_b.poly.id), verifier_tracker.transfer_prover_comm(bag_b.selector.id), bag_b.num_vars());
        let range_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(range_bag.poly.id), verifier_tracker.transfer_prover_comm(range_bag.selector.id), range_bag.num_vars());
        SetDisjointIOP::<E, PCS>::verify(
            verifier_tracker,
            &bag_a_comm,
            &bag_b_comm,
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
    fn set_disjoint_test() {
        let res = test_set_disjoint();
        res.unwrap();
    }
}