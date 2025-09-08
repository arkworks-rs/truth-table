use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    prover::structs::polynomial::TrackedPoly,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};

use super::{AndCheckPIOP, AndCheckProverInput, AndCheckVerifierInput};
// Test cases for multiplicity check, where the active and multiplicative
// columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn and_check_is_complete() -> SnarkResult<()> {
    and_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        vec![
            to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
            to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        ],
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
    )?;
    and_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        vec![
            to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr),
            to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr),
        ],
        to_field_vec!([0, 1, 1, 1, 1, 0, 1, 1], Fr),
    )?;
    and_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        vec![
            to_field_vec!([0, 0, 0, 0, 0, 0, 0, 0], Fr),
            to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        ],
        to_field_vec!([0, 0, 0, 0, 0, 0, 0, 0], Fr),
    )?;
    Ok(())
}

#[test]
fn and_check_is_sound() -> SnarkResult<()> {
    and_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        vec![
            to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr),
            to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        ],
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
    )?;

    Ok(())
}

fn and_check_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    in_values: Vec<Vec<Fr>>,
    res_values: Vec<Fr>,
) -> SnarkResult<()> {
    let err = and_check_test_helper::<Fr, MvPCS, UvPCS>(nv, in_values, res_values).unwrap_err();

    #[cfg(feature = "honest-prover")]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim
                )
            )
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(_)
            )
        ));
    }

    Ok(())
}

fn and_check_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    in_values: Vec<Vec<Fr>>,
    res_values: Vec<Fr>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;
    let res_activator_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &res_values))?;
    let in_activator_polys: Vec<TrackedPoly<Fr, MvPCS, UvPCS>> = in_values
        .iter()
        .map(|in_evals| {
            prover
                .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, in_evals))
                .unwrap()
        })
        .collect();
    let and_check_prover_input = AndCheckProverInput {
        in_activator_polys: in_activator_polys.clone(),
        res_activator_poly,
    };
    AndCheckPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, and_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let actv_id = verifier.peek_next_id();
    let res_activator_orcl = verifier.track_mv_com_by_id(actv_id)?;
    let in_activator_orcls = in_activator_polys
        .iter()
        .map(|activator_poly| verifier.track_mv_com_by_id(activator_poly.id()).unwrap())
        .collect();
    let and_check_verifier_input = AndCheckVerifierInput {
        in_activator_orcls,
        res_activator_orcl,
    };

    AndCheckPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, and_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
