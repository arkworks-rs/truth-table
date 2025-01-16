    use arithmetic::{ark_ff, ark_poly, mle::mat::random_permutation_mles};
use ark_ec::pairing::Pairing;
    use ark_ff::{Field, PrimeField};
    use ark_poly::DenseMultilinearExtension;
    use ark_std::{Zero, One};
    use ark_test_curves::bls12_381::{Bls12_381, Fr};
    use crypto::{ark_ec, pcs::{multilinear_kzg::MultilinearKzgPCS, PolynomialCommitmentScheme}};
    use kit::ark_std;

    use ark_std::test_rng;
    use ark_std::rand::prelude::SliceRandom;

    use crate::{
        tracker::prelude::*,
        col_toolbox::multiplicity_check::MultiplicityCheck, 
    };

    #[test]
    // Sets up randomized inputs for testing ColMultitoolCheck
    fn test_multiplicity_check() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 4;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init f, mf, and a permutation vec, and build g, mg based off of it
        let f = random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let mf =random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let f_evals: Vec<Fr> = f.evaluations.clone();
        let mf_evals: Vec<Fr> = mf.evaluations.clone();
        let mut permute_vec: Vec<usize> = (0..f_evals.len()).collect();
        permute_vec.shuffle(&mut rng);
        let g_evals: Vec<Fr> = permute_vec.iter().map(|&i| f_evals[i]).collect();
        let mg_evals: Vec<Fr> = permute_vec.iter().map(|&i| mf_evals[i]).collect();
        let g = DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone());
        let mg = DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone());

        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // Good Path 1: they are a correct permutation, selector is all ones
        print!("test_multiplicity_check Good path 1: ");
        let one_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); f_evals.len()]);
        let f_sel = one_mle.clone();
        let g_sel = one_mle.clone();
        test_multiplicity_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f.clone()], &[f_sel.clone()], &[mf.clone()], &[g.clone()], &[g_sel.clone()], &[mg.clone()])?;
        println!("passed");

        // Good Path 2: selector includes zeros
        print!("test_multiplicity_check Good path 2 (selector includes zeros): ");
        let f2_evals = f_evals.clone();
        let mut f2_sel_evals = vec![Fr::one(); f_evals.len()];
        f2_sel_evals[permute_vec[0]] = Fr::zero();
        let g2_evals = g_evals.clone();
        let mut g2_sel_evals = vec![Fr::one(); g_evals.len()];
        g2_sel_evals[0] = Fr::zero();

        let f2 = DenseMultilinearExtension::from_evaluations_vec(nv, f2_evals.clone());
        let f2_sel =DenseMultilinearExtension::from_evaluations_vec(nv, f2_sel_evals.clone());
        let g2 =DenseMultilinearExtension::from_evaluations_vec(nv, g2_evals.clone());
        let g2_sel = DenseMultilinearExtension::from_evaluations_vec(nv, g2_sel_evals.clone());
        test_multiplicity_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f2.clone()], &[f2_sel.clone()], &[mf.clone()],&[g2.clone()], &[g2_sel.clone()], &[mg.clone()])?;
        println!("passed");
        println!();


        // Good Path 3: f is split into two polynomials
        print!("test_multiplicity_check Good path 3 (f is split into two half-sized polynomials): ");
        println!();
        let half_one_poly = DenseMultilinearExtension::from_evaluations_vec(nv-1, vec![Fr::one(); f_evals.len()/2]);
        let f3a_evals = f_evals.clone()[..f_evals.len()/2].to_vec();
        let f3b_evals = f_evals.clone()[f_evals.len()/2..].to_vec();
        let mf3a_evals = mf_evals.clone()[..mf_evals.len()/2].to_vec();
        let mf3b_evals = mf_evals.clone()[mf_evals.len()/2..].to_vec();
        let f3a = DenseMultilinearExtension::from_evaluations_vec(nv-1, f3a_evals.clone());
        let mf3a = DenseMultilinearExtension::from_evaluations_vec(nv-1, mf3a_evals.clone());
        let f3b = DenseMultilinearExtension::from_evaluations_vec(nv-1, f3b_evals.clone());
        let mf3b = DenseMultilinearExtension::from_evaluations_vec(nv-1, mf3b_evals.clone());
        test_multiplicity_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f3a, f3b], &[half_one_poly.clone(), half_one_poly.clone()], &[mf3a.clone(), mf3b.clone()], &[g.clone()], &[g_sel.clone()], &[mg.clone()])?;
        println!("passed");

        // gopd path 4: multiplivities include zeros and twos instead of just ones
        print!("test_multiplicity_check Good path 4: ");
        let f_nums      = vec![0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let f_sel_nums  = vec![1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mf_nums     = vec![1; 16];
        let g_nums      = vec![0, 1, 2, 3, 4, 0, 0, 0];
        let g_sel_nums  = vec![1, 1, 1, 1, 1, 0, 0, 0];
        let mg_nums     = vec![2, 1, 1, 1, 1, 0, 0, 0];
        let f4_mle = DenseMultilinearExtension::from_evaluations_vec(4, f_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let f4_sel_mle = DenseMultilinearExtension::from_evaluations_vec(4, f_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mf4_mle = DenseMultilinearExtension::from_evaluations_vec(4, mf_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let g4_mle = DenseMultilinearExtension::from_evaluations_vec(3, g_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let g4_sel_mle = DenseMultilinearExtension::from_evaluations_vec(3, g_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mg4_mle = DenseMultilinearExtension::from_evaluations_vec(3, mg_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        test_multiplicity_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f4_mle.clone()], &[f4_sel_mle.clone()], &[mf4_mle.clone()], &[g4_mle.clone()], &[g4_sel_mle.clone()], &[mg4_mle.clone()])?;
        println!("passed");

        // good paths passed. Now check bad paths
        let h = random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let h_sel = one_mle.clone();
        let mh = random_permutation_mles(nv, 1, &mut rng)[0].clone();

        // incorrect multiplicities
        let bad_result1 = test_multiplicity_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &[f.clone()], &[f_sel.clone()], &[mf.clone()],&[h], &[h_sel],  &[mf.clone()]);
        assert!(bad_result1.is_err());
        println!("bad path 1 passed");
        // incorrect polynomials
        let bad_result2 = test_multiplicity_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &[f.clone()], &[f_sel.clone()], &[mf.clone()], &[f.clone()], &[f_sel.clone()],&[mh]);
        assert!(bad_result2.is_err());
        println!("bad path 2 passed");
        // incorrect selectors
        let bad_result3 = test_multiplicity_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &[f.clone()], &[f_sel.clone()], &[mf.clone()], &[g2.clone()], &[g2_sel.clone()],  &[mg.clone()]);
        assert!(bad_result3.is_err());
        println!("bad path 3 passed");

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies ColMultitoolCheck
        fn test_multiplicity_check_helper<F:Field+PrimeField, PCS> (
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        fs: &[DenseMultilinearExtension<F>],
        f_sels:&[DenseMultilinearExtension<F>],
        mfs: &[DenseMultilinearExtension<F>],
        gs: &[DenseMultilinearExtension<F>],
        g_sels: &[DenseMultilinearExtension<F>],
        mgs: &[DenseMultilinearExtension<F>],
    ) -> Result<(), PolyIOPErrors>  where
    PCS: PolynomialCommitmentScheme<F>,{
        // Set up prover_tracker and prove
        let f_polys_vec: Vec<TrackedPoly<F, PCS>> = fs.iter().map(|p| prover_tracker.track_and_commit_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let f_sel_polys_vec: Vec<TrackedPoly<F, PCS>> = f_sels.iter().map(|p| prover_tracker.track_and_commit_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let mf_polys_vec: Vec<TrackedPoly<F, PCS>> = mfs.iter().map(|p| prover_tracker.track_and_commit_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let g_polys_vec: Vec<TrackedPoly<F, PCS>> = gs.iter().map(|p| prover_tracker.track_and_commit_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let g_sel_polys_vec: Vec<TrackedPoly<F, PCS>> = g_sels.iter().map(|p| prover_tracker.track_and_commit_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let mg_polys_vec: Vec<TrackedPoly<F, PCS>> = mgs.iter().map(|p| prover_tracker.track_and_commit_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;

        let f_cols_vec: Vec<Col<F, PCS>> = f_polys_vec.iter()
            .zip(f_sel_polys_vec.iter())
            .map(|(f, f_sel)| Col::new(f.clone(), f_sel.clone()))
            .collect();
        let f_cols: &[Col<F, PCS>] = &f_cols_vec;

        let g_cols_vec: Vec<Col<F, PCS>> = g_polys_vec.iter()
            .zip(g_sel_polys_vec.iter())
            .map(|(g, g_sel)| Col::new(g.clone(), g_sel.clone()))
            .collect();
        let g_cols: &[Col<F, PCS>] = &g_cols_vec;

        MultiplicityCheck::<F, PCS>::prove(
            prover_tracker,
            f_cols,
            g_cols,
            &mf_polys_vec,
            &mg_polys_vec
        )?;
        let proof = prover_tracker.compile_proof()?;
        
        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);

        let f_comms_vec: Vec<TrackedComm<F, PCS>> = f_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<F, PCS>>>();
        let f_sel_comms_vec: Vec<TrackedComm<F, PCS>> = f_sel_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<F, PCS>>>();
        let mf_comms_vec: Vec<TrackedComm<F, PCS>> = mf_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<F, PCS>>>();
        let g_comms_vec: Vec<TrackedComm<F, PCS>> = g_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<F, PCS>>>();
        let g_sel_comms_vec: Vec<TrackedComm<F, PCS>> = g_sel_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<F, PCS>>>();
        let mg_comms_vec: Vec<TrackedComm<F, PCS>> = mg_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<F, PCS>>>();

        let f_cols_vec: Vec<ColComm<F, PCS>> = f_comms_vec.iter()
            .zip(f_sel_comms_vec.iter())
            .map(|(f, f_sel)| ColComm::new(f.clone(), f_sel.clone(), fs[0].num_vars))
            .collect();
        let f_cols: &[ColComm<F, PCS>] = &f_cols_vec;

        let g_cols_vec: Vec<ColComm<F, PCS>> = g_comms_vec.iter()
            .zip(g_sel_comms_vec.iter())
            .map(|(g, g_sel)| ColComm::new(g.clone(), g_sel.clone(), gs[0].num_vars))
            .collect();
        let g_cols: &[ColComm<F, PCS>] = &g_cols_vec;
        MultiplicityCheck::<F, PCS>::verify(verifier_tracker, f_cols, g_cols, &mf_comms_vec, &mg_comms_vec)?;
        verifier_tracker.verify_claims()?;

        // check that the ProverTracker and VerifierTracker are in the same state at completion
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.num_tracked_polys, v_tracker.num_tracked_polys);
        assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);
        
        Ok(())
    }

 