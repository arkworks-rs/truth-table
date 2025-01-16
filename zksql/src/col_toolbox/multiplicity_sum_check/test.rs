use arithmetic::mle::mat::random_permutation_mles;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use crypto::ark_ec;
#[cfg(test)]
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_std::{One, Zero};

use ark_std::test_rng;
use crypto::pcs::multilinear_kzg::MultilinearKzgPCS;
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std;

use crate::col_toolbox::multiplicity_sum_check::MultiplicitySumCheck;
use crate::tracker::prelude::{Col, ColComm, PolyIOPErrors, ProverTrackerRef, VerifierTrackerRef};


// Sets up randomized inputs for testing MultiplicitySumCheck
// TODO: Break up the tests into smaller functions
#[test]
fn test_col_sum() -> Result<(), PolyIOPErrors> {
    // testing params
    let nv = 8;
    let mut rng = test_rng();

    // PCS params
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
    let (pcs_prover_param, pcs_verifier_param) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

    // randomly init a permutation vec, and build stuff off of it
    let gen = random_permutation_mles(nv, 1, &mut rng)[0].clone();
    let gen_evals: Vec<Fr> = gen.evaluations.clone();

    // Create Trackers
    let mut prover_tracker: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
    let mut verifier_tracker: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

    // good path 1, f0 and f1 are the same size
    let one_poly = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![Fr::one(); 2_usize.pow(nv as u32)],
    );
    let f0_evals = gen_evals.clone()[..gen_evals.len() / 2].to_vec();
    let f1_evals = gen_evals.clone()[gen_evals.len() / 2..].to_vec();
    let half_one_poly =
        DenseMultilinearExtension::from_evaluations_vec(nv - 1, vec![Fr::one(); f0_evals.len()]);
    let g_evals = gen_evals.clone();
    let f0 = DenseMultilinearExtension::from_evaluations_vec(nv - 1, f0_evals.clone());
    let f0_sel = half_one_poly.clone();
    let f1 = DenseMultilinearExtension::from_evaluations_vec(nv - 1, f1_evals.clone());
    let f1_sel = half_one_poly.clone();
    let g = DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone());
    let g_sel = one_poly.clone();

    print!("test_colsum good path 1 (f0 and f1 are both half sized): ");
    test_colsum_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker,
        &mut verifier_tracker,
        &f0.clone(),
        &f0_sel.clone(),
        &f1.clone(),
        &f1_sel.clone(),
        &g.clone(),
        &g_sel.clone(),
    )?;
    println!("passed");

    // good path 2, f0 and f1 are different sized
    print!("test_colsum good path 2 (f0 and f1 are different sized: ");
    let f0_evals = gen_evals.clone()[..gen_evals.len() / 2].to_vec();
    let f0_sel_evals = vec![Fr::one(); f0_evals.len()];
    let f1_evals = gen_evals.clone()[gen_evals.len() / 2..(gen_evals.len() * 3 / 4)].to_vec();
    let f1_sel_evals = vec![Fr::one(); f1_evals.len()];

    let mut g_evals = gen_evals.clone();
    for i in (gen_evals.len() * 3 / 4)..gen_evals.len() {
        g_evals[i] = Fr::zero();
    }
    let mut g_sel_evals = vec![Fr::one(); g_evals.len()];
    for i in (gen_evals.len() * 3 / 4)..gen_evals.len() {
        g_sel_evals[i] = Fr::zero();
    }

    let f0 = DenseMultilinearExtension::from_evaluations_vec(nv - 1, f0_evals.clone());
    let f0_sel = DenseMultilinearExtension::from_evaluations_vec(nv - 1, f0_sel_evals.clone());
    let f1 = DenseMultilinearExtension::from_evaluations_vec(nv - 2, f1_evals.clone());
    let f1_sel = DenseMultilinearExtension::from_evaluations_vec(nv - 2, f1_sel_evals.clone());
    let g = DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone());
    let g_sel = DenseMultilinearExtension::from_evaluations_vec(nv, g_sel_evals.clone());

    test_colsum_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker,
        &mut verifier_tracker,
        &f0.clone(),
        &f0_sel.clone(),
        &f1.clone(),
        &f1_sel.clone(),
        &g.clone(),
        &g_sel.clone(),
    )?;
    println!("passed");

    // bad path
    print!("test_colsum bad path 1 (lhs doesn't match rhs): ");
    let mut bad_f0_evals = f0_evals.clone();
    bad_f0_evals[0] = Fr::one();
    bad_f0_evals[1] = Fr::one();
    let bad_f0 = DenseMultilinearExtension::from_evaluations_vec(nv - 1, bad_f0_evals.clone());
    let bad_f0_sel =
        DenseMultilinearExtension::from_evaluations_vec(nv - 1, vec![Fr::one(); f0_evals.len()]);
    let bad_result1 = test_colsum_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker.deep_copy(),
        &mut verifier_tracker.deep_copy(),
        &bad_f0.clone(),
        &bad_f0_sel.clone(),
        &f1.clone(),
        &f1_sel.clone(),
        &g.clone(),
        &g_sel.clone(),
    );
    assert!(bad_result1.is_err());
    println!("passed");

    // exit successfully
    Ok(())
}

// Given inputs, calls and verifies MultiplicitySumCheck
fn test_colsum_helper<F: PrimeField + PrimeField, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    f0: &DenseMultilinearExtension<F>,
    f0_sel: &DenseMultilinearExtension<F>,
    f1: &DenseMultilinearExtension<F>,
    f1_sel: &DenseMultilinearExtension<F>,
    g: &DenseMultilinearExtension<F>,
    g_sel: &DenseMultilinearExtension<F>,
) -> Result<(), PolyIOPErrors>
where
    PCS: PolynomialCommitmentScheme<F>,
{
    let f0_nv = f0.num_vars;
    let f1_nv = f1.num_vars;
    let g_nv = g.num_vars;
    // Set up prover_tracker and prove
    let f0_col = Col::new(
        prover_tracker.track_and_commit_poly(f0.clone())?,
        prover_tracker.track_and_commit_poly(f0_sel.clone())?,
    );
    let f1_col = Col::new(
        prover_tracker.track_and_commit_poly(f1.clone())?,
        prover_tracker.track_and_commit_poly(f1_sel.clone())?,
    );
    let g_col = Col::new(
        prover_tracker.track_and_commit_poly(g.clone())?,
        prover_tracker.track_and_commit_poly(g_sel.clone())?,
    );

    MultiplicitySumCheck::<F, PCS>::prove(prover_tracker, &f0_col, &f1_col, &g_col)?;
    let proof = prover_tracker.compile_proof()?;

    // set up verifier tracker, create subclaims, and verify IOPProofs
    verifier_tracker.set_compiled_proof(proof);
    let f0_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(f0_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(f0_col.actv_poly.id),
        f0_nv,
    );
    let f1_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(f1_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(f1_col.actv_poly.id),
        f1_nv,
    );
    let g_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(g_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(g_col.actv_poly.id),
        g_nv,
    );
    MultiplicitySumCheck::<F, PCS>::verify(
        verifier_tracker,
        &f0_col_comm,
        &f1_col_comm,
        &g_col_comm,
    )?;
    verifier_tracker.verify_claims()?;

    // check that the ProverTracker and VerifierTracker are in the same state
    let p_tracker = prover_tracker.clone_underlying_tracker();
    let v_tracker = verifier_tracker.clone_underlying_tracker();
    assert_eq!(p_tracker.num_tracked_polys, v_tracker.num_tracked_polys);
    assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
    assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);

    Ok(())
}
