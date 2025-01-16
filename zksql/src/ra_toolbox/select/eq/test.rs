use super::PolyIOPErrors;
use crate::{
    ra_piop::select::eq::{ColComm, SelEqPIOP},
    subroutines::{MultilinearKzgPCS, PolynomialCommitmentScheme},
    tracker::prelude::{Col, ProverTrackerRef, VerifierTrackerRef},
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{test_rng, One, Zero};
use datafusion::sql::sqlparser::ast::Select;

#[test]
// Sets up randomized inputs for testing SelectEq
fn test_select_eq_with_advice() -> Result<(), PolyIOPErrors> {
    // testing params
    let nv = 3;
    let mut rng = test_rng();

    // PCS params
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
    let (pcs_prover_param, pcs_verifier_param) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

    // f=[1,5,3,4,5,6,7,8]
    let input_poly = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![
            Fr::one(),
            Fr::from(5u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(6u64),
            Fr::from(7u64),
            Fr::from(8u64),
        ],
    );
    let input_sel = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![Fr::one(); 2_usize.pow(nv as u32)],
    );

    let output_sel = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![
            Fr::zero(),
            Fr::one(),
            Fr::zero(),
            Fr::zero(),
            Fr::one(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
        ],
    );

    // Create Trackers
    let mut prover_tracker: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
    let mut verifier_tracker: VerifierTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>> =
        VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

    // Good path 1: described above
    print!("test_select_eq_with_advice_helper good path 1:");
    test_select_eq_helper::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, MultilinearKzgPCS<Bls12_381>>(
        &mut prover_tracker,
        &mut verifier_tracker,
        &input_poly.clone(),
        &input_sel.clone(),
        &input_poly.clone(),
        &output_sel.clone(),
    )?;
    println!("passed");

    // exit successfully
    Ok(())
}

// Given inputs, calls and verifies SelectEq
fn test_select_eq_helper<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    intput_poly: &DenseMultilinearExtension<F>,
    input_sel: &DenseMultilinearExtension<F>,
    output_poly: &DenseMultilinearExtension<F>,
    output_sel: &DenseMultilinearExtension<F>,
) -> Result<(), PolyIOPErrors>
where
    PCS: PolynomialCommitmentScheme<F>,
{
    let f_nv = intput_poly.num_vars;
    let g_nv = output_poly.num_vars;
    // Set up prover_tracker and prove
    let input_col = Col::new(
        prover_tracker.track_and_commit_poly(intput_poly.clone())?,
        prover_tracker.track_and_commit_poly(input_sel.clone())?,
    );
    let output_col = Col::new(
        prover_tracker.track_and_commit_poly(output_poly.clone())?,
        prover_tracker.track_and_commit_poly(output_sel.clone())?,
    );

    SelEqPIOP::<E, PCS>::prove(
        prover_tracker,
        &input_col,
        &output_col,
        E::ScalarField::from(5u64),
    )?;
    let proof = prover_tracker.compile_proof()?;

    // set up verifier tracker, create subclaims, and verify IOPProofs
    verifier_tracker.set_compiled_proof(proof);

    let input_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(input_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(input_col.actv_poly.id),
        f_nv,
    );
    let output_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(output_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(output_col.actv_poly.id),
        g_nv,
    );

    SelEqPIOP::<E, PCS>::verify(
        verifier_tracker,
        &input_col_comm,
        &output_col_comm,
        E::ScalarField::from(5u64),
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
