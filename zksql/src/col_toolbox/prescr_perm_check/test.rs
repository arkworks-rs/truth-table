use arithmetic::mle::mat::random_permutation_mles;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use crypto::ark_ec;
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_std::{One, Zero};

use ark_std::{rand::prelude::SliceRandom, test_rng};
use crypto::pcs::multilinear_kzg::MultilinearKzgPCS;
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std;

use crate::{col_toolbox::prescr_perm_check::PrescrPermPIOP, tracker::prelude::*};

#[test]
// Sets up randomized inputs for testing PrescrPermPIOP
fn test_prescr_perm_check() -> Result<(), PolyIOPErrors> {
    // testing params
    let nv = 3;
    let mut rng = test_rng();

    // PCS params
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
    let (pcs_prover_param, pcs_verifier_param) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

    // Create Trackers
    let mut prover_tracker: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
    let mut verifier_tracker: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

    // randomly init f, and a permuation vec, and build g off of it
    let one_poly = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![Fr::one(); 2_usize.pow(nv as u32)],
    );
    let f = random_permutation_mles(nv, 1, &mut rng)[0].clone();
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
    test_prescr_perm_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker,
        &mut verifier_tracker,
        &f.clone(),
        &f_sel.clone(),
        &g.clone(),
        &g_sel.clone(),
        &perm.clone(),
    )?;
    println!("test_presc_perm good path 1 passed");

    // // bad path 1 - different elements
    // let mut bad_f_evals = f_evals.clone();
    // bad_f_evals[0] = Fr::one();
    // bad_f_evals[1] = Fr::one();
    // let bad_f = DenseMultilinearExtension::from_evaluations_vec(nv, bad_f_evals.clone());
    // let bad_f_sel = one_poly.clone();
    // let bad_result1 = test_prescr_perm_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
    //     &mut prover_tracker.deep_copy(),
    //     &mut verifier_tracker.deep_copy(),
    //     &bad_f.clone(),
    //     &bad_f_sel.clone(),
    //     &g.clone(),
    //     &g_sel.clone(),
    //     &perm.clone(),
    // );
    // assert!(bad_result1.is_err());
    // println!("test_presc_perm bad path 1 passed");

    // // bad path 2 - f and g are a different permutation than perm
    // let mut bad_perm_evals = perm_evals.clone();
    // let old_0_eval = perm_evals[0];
    // bad_perm_evals[0] = bad_perm_evals[1];
    // bad_perm_evals[1] = old_0_eval;
    // let bad_perm = DenseMultilinearExtension::from_evaluations_vec(nv, bad_perm_evals.clone());
    // let bad_result2 = test_prescr_perm_check_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
    //     &mut prover_tracker.deep_copy(),
    //     &mut verifier_tracker.deep_copy(),
    //     &f.clone(),
    //     &f_sel.clone(),
    //     &g.clone(),
    //     &g_sel.clone(),
    //     &bad_perm.clone(),
    // );
    // assert!(bad_result2.is_err());
    // println!("test_presc_perm bad path 2 passed");

    // exit successfully
    Ok(())
}

// Given inputs, calls and verifies PrescrPermPIOP
fn test_prescr_perm_check_helper<F: PrimeField + PrimeField, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    f: &DenseMultilinearExtension<F>,
    f_sel: &DenseMultilinearExtension<F>,
    g: &DenseMultilinearExtension<F>,
    g_sel: &DenseMultilinearExtension<F>,
    perm: &DenseMultilinearExtension<F>,
) -> Result<(), PolyIOPErrors>
where
    PCS: PolynomialCommitmentScheme<F>,
{
    let nv = f.num_vars;
    // Set up prover_tracker and prove
    let f_col = Col::new(
        prover_tracker.track_and_commit_poly(f.clone())?,
        prover_tracker.track_and_commit_poly(f_sel.clone())?,
    );
    let g_col = Col::new(
        prover_tracker.track_and_commit_poly(g.clone())?,
        prover_tracker.track_and_commit_poly(g_sel.clone())?,
    );
    let perm = prover_tracker.track_and_commit_poly(perm.clone())?;

    dbg!(f_col.inner_poly.evaluations());
    dbg!(g_col.inner_poly.evaluations());
    dbg!(perm.evaluations());
    
    PrescrPermPIOP::<F, PCS>::prove(prover_tracker, &f_col, &g_col, &perm)?;
    let proof = prover_tracker.compile_proof()?;

    // set up verifier tracker, create subclaims, and verify IOPProofs
    verifier_tracker.set_compiled_proof(proof);
    let f_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(f_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(f_col.actv_poly.id),
        nv,
    );
    let g_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(g_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(g_col.actv_poly.id),
        nv,
    );
    let perm_comm = verifier_tracker.transfer_prover_comm(perm.id);
    PrescrPermPIOP::<F, PCS>::verify(verifier_tracker, &f_col_comm, &g_col_comm, &perm_comm)?;
    verifier_tracker.verify_claims()?;

    // check that the ProverTracker and VerifierTracker are in the same state
    let p_tracker = prover_tracker.clone_underlying_tracker();
    let v_tracker = verifier_tracker.clone_underlying_tracker();
    assert_eq!(p_tracker.num_tracked_polys, v_tracker.num_tracked_polys);
    assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
    assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);

    Ok(())
}
