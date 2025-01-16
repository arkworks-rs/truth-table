use arithmetic::mle::mat::random_permutation_mles;
use arithmetic::{ark_ff, ark_poly};
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_std::One;

use ark_std::test_rng;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use crypto::ark_ec;
use crypto::pcs::multilinear_kzg::MultilinearKzgPCS;
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std;

use crate::{col_toolbox::eq_check::EqCheckIOP, tracker::prelude::*};

// Sets up randomized inputs for testing EqCheckCheck
#[test]
fn test_EqCheck() -> Result<(), PolyIOPErrors> {
    // testing params
    let nv = 8;
    let mut rng = test_rng();

    // PCS params
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
    let (pcs_prover_param, pcs_verifier_param) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

    // randomly init f, mf, and a permutation vec, and build g, mg based off of it
    let f = random_permutation_mles(nv, 1, &mut rng)[0].clone();
    let g = random_permutation_mles(nv, 1, &mut rng)[0].clone();
    let one_poly = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![Fr::one(); 2_usize.pow(nv as u32)],
    );
    let f_sel = one_poly.clone();
    let g_sel = one_poly.clone();

    // Create Trackers
    let mut prover_tracker: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
    let mut verifier_tracker: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

    // Good Path
    test_EqCheck_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker,
        &mut verifier_tracker,
        &f.clone(),
        &f_sel.clone(),
        &g.clone(),
        &g_sel.clone(),
    )?;
    println!("Good path passed");

    // Bad path
    let mut h_evals = f.evaluations.clone();
    h_evals[0] = h_evals[0] + Fr::one();
    let h = DenseMultilinearExtension::from_evaluations_vec(f.num_vars, h_evals);
    let h_sel = one_poly.clone();

    let bad_result1 = test_EqCheck_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker.deep_copy(),
        &mut verifier_tracker.deep_copy(),
        &f.clone(),
        &f_sel.clone(),
        &h.clone(),
        &h_sel.clone(),
    );
    assert!(bad_result1.is_err());
    println!("Bad path passed");

    // exit successfully
    Ok(())
}

// Given inputs, calls and verifies EqCheckCheck
fn test_EqCheck_helper<F:Field+PrimeField, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    f: &DenseMultilinearExtension<F>,
    f_sel: &DenseMultilinearExtension<F>,
    g: &DenseMultilinearExtension<F>,
    g_sel: &DenseMultilinearExtension<F>,
) -> Result<(), PolyIOPErrors>
where
    PCS: PolynomialCommitmentScheme<F>,
{
    let f_nv = f.num_vars;
    let g_nv = g.num_vars;
    // Set up prover_tracker and prove
    let f_col = Col::new(
        prover_tracker.track_and_commit_poly(f.clone())?,
        prover_tracker.track_and_commit_poly(f_sel.clone())?,
    );
    let g_col = Col::new(
        prover_tracker.track_and_commit_poly(g.clone())?,
        prover_tracker.track_and_commit_poly(g_sel.clone())?,
    );

    EqCheckIOP::<F, PCS>::prove(prover_tracker, &f_col, &g_col)?;
    let proof = prover_tracker.compile_proof()?;

    // set up verifier tracker, create subclaims, and verify IOPProofs
    verifier_tracker.set_compiled_proof(proof);
    let f_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(f_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(f_col.actv_poly.id),
        f_nv,
    );
    let g_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(g_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(g_col.actv_poly.id),
        g_nv,
    );
    EqCheckIOP::<F, PCS>::verify(verifier_tracker, &f_col_comm, &g_col_comm)?;
    verifier_tracker.verify_claims()?;

    // check that the ProverTracker and VerifierTracker are in the same state
    let p_tracker = prover_tracker.clone_underlying_tracker();
    let v_tracker = verifier_tracker.clone_underlying_tracker();
    assert_eq!(p_tracker.num_tracked_polys, v_tracker.num_tracked_polys);
    assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
    assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);

    Ok(())
}

