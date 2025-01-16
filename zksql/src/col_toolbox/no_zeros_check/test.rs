use arithmetic::{ark_ff, ark_poly};
use ark_ec::pairing::Pairing;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_std::{rand::Rng, One};

use ark_std::test_rng;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use crypto::ark_ec;
use crypto::pcs::multilinear_kzg::MultilinearKzgPCS;
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std;

use crate::{col_toolbox::no_zeros_check::NoZerosCheck, tracker::prelude::*};

// TODO: There are some lines that appear at the beginning of almost every test,
// do sth for that --> macro?
#[test]
fn no_zeros_check_accepts() -> Result<(), PolyIOPErrors> {
    // testing params
    let nv = 8;
    let mut rng = test_rng();

    // PCS params
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
    let (pcs_prover_param, pcs_verifier_param) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

    // randomly init f, mf, and a permutation vec, and build g, mg based off of it
    let one_poly = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![Fr::one(); 2_usize.pow(nv as u32)],
    );
    let f = one_poly.clone();
    let f_actv = one_poly.clone();

    // Create Trackers
    let mut prover_tracker: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
    let mut verifier_tracker: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

    // Good Path
    test_col_nozeros_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker,
        &mut verifier_tracker,
        &f.clone(),
        &f_actv.clone(),
    )?;
    Ok(())
}

#[test]
fn no_zeros_check_rejects() -> Result<(), PolyIOPErrors> {
    // testing params
    let nv = 8;
    let mut rng = test_rng();

    // PCS params
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
    let (pcs_prover_param, pcs_verifier_param) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

    // randomly init f, mf, and a permutation vec, and build g, mg based off of it
    let one_poly = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![Fr::one(); 2_usize.pow(nv as u32)],
    );
    let f = one_poly.clone();

    // Create Trackers
    let prover_tracker: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
    let verifier_tracker: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);
    let mut f_evals = f.evaluations.clone();
    let rand_zero_index = rng.gen_range(0..f_evals.len());
    f_evals[rand_zero_index] = Fr::ZERO;
    let h = DenseMultilinearExtension::from_evaluations_vec(f.num_vars, f_evals);
    let f_actv = one_poly.clone();

    let bad_result1 = test_col_nozeros_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker.deep_copy(),
        &mut verifier_tracker.deep_copy(),
        &h.clone(),
        &f_actv.clone(),
    );
    assert!(bad_result1.is_err());

    // exit successfully
    Ok(())
}

// Given inputs, calls and verifies EqCheckCheck
fn test_col_nozeros_helper<F: PrimeField + PrimeField, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    f: &DenseMultilinearExtension<F>,
    f_actv: &DenseMultilinearExtension<F>,
) -> Result<(), PolyIOPErrors>
where
    PCS: PolynomialCommitmentScheme<F>,
{
    let f_nv = f.num_vars;
    // Set up prover_tracker and prove
    let f_col = Col::new(
        prover_tracker.track_and_commit_poly(f.clone())?,
        prover_tracker.track_and_commit_poly(f_actv.clone())?,
    );

    NoZerosCheck::<F, PCS>::prove(prover_tracker, &f_col)?;
    let proof = prover_tracker.compile_proof()?;

    // set up verifier tracker, create subclaims, and verify IOPProofs
    verifier_tracker.set_compiled_proof(proof);
    let f_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(f_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(f_col.actv_poly.id),
        f_nv,
    );
    NoZerosCheck::<F, PCS>::verify(verifier_tracker, &f_col_comm)?;
    verifier_tracker.verify_claims()?;

    // check that the ProverTracker and VerifierTracker are in the same state
    let p_tracker = prover_tracker.clone_underlying_tracker();
    let v_tracker = verifier_tracker.clone_underlying_tracker();
    assert_eq!(p_tracker.num_tracked_polys, v_tracker.num_tracked_polys);
    assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
    assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);

    Ok(())
}
