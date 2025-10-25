use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};

use super::{
    PredicateLimitCheck, PredicateLimitCheckProverInput, PredicateLimitCheckVerifierInput,
};

#[test]
fn predicate_limit_check_is_complete() -> SnarkResult<()> {
    predicate_limit_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 0, 1, 1, 1, 0, 1], Fr),
        to_field_vec!([0, 0, 0, 0, 0, 0, 0, 0], Fr),
        0,
    )?;

    predicate_limit_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 0, 1, 1, 1, 0, 1], Fr),
        to_field_vec!([1, 0, 0, 1, 1, 0, 0, 0], Fr),
        3,
    )?;

    predicate_limit_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 1, 0, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 0, 1, 0, 1, 1, 1, 1], Fr),
        6,
    )?;

    predicate_limit_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 1, 1, 1, 0, 0, 0, 0], Fr),
        to_field_vec!([1, 1, 1, 0, 0, 0, 0, 0], Fr),
        3,
    )?;

    Ok(())
}

#[test]
fn predicate_limit_check_is_sound() -> SnarkResult<()> {
    predicate_limit_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 0, 1, 1, 1, 0, 1], Fr),
        to_field_vec!([1, 1, 1, 1, 0, 0, 0, 0], Fr),
        3,
    )?;

    predicate_limit_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 0, 1, 1, 1, 0, 1], Fr),
        to_field_vec!([1, 0, 0, 0, 0, 0, 0, 0], Fr),
        2,
    )?;

    predicate_limit_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 0, 3, 4, 0, 5, 6], Fr),
        to_field_vec!([1, 2, 0, 3, 4, 0, 5, 6], Fr),
        3,
    )?;

    predicate_limit_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 0, 1, 0, 0, 1, 0], Fr),
        to_field_vec!([1, 0, 0, 1, 0, 0, 0, 0], Fr),
        0,
    )?;

    predicate_limit_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([5, 0, 6, 0, 7, 0, 8, 0], Fr),
        to_field_vec!([5, 0, 6, 0, 7, 0, 8, 0], Fr),
        7,
    )?;

    Ok(())
}

fn predicate_limit_check_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    log_size: usize,
    input_evals: Vec<Fr>,
    output_evals: Vec<Fr>,
    limit: usize,
) -> SnarkResult<()> {
    let err = predicate_limit_check_test_helper::<Fr, MvPCS, UvPCS>(
        log_size,
        input_evals,
        output_evals,
        limit,
    )
    .unwrap_err();

    #[cfg(feature = "honest-prover")]
    {
        use ark_piop::prover::errors::{HonestProverError, ProverError};
        assert!(matches!(
            err,
            SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim
            ))
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        use ark_piop::verifier::errors::VerifierError;
        assert!(matches!(
            err,
            SnarkError::VerifierError(VerifierError::VerifierCheckFailed(_))
        ));
    }

    Ok(())
}

fn predicate_limit_check_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    log_size: usize,
    input_evals: Vec<Fr>,
    output_evals: Vec<Fr>,
    limit: usize,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    let input_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, input_evals))?;
    let output_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, output_evals))?;

    let prover_input = PredicateLimitCheckProverInput {
        input_predicate: input_poly.clone(),
        output_predicate: output_poly.clone(),
        limit,
    };
    PredicateLimitCheck::<Fr, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let input_oracle = verifier.track_mv_com_by_id(input_poly.id())?;
    let output_oracle = verifier.track_mv_com_by_id(output_poly.id())?;
    let verifier_input = PredicateLimitCheckVerifierInput {
        input_predicate_oracle: input_oracle,
        output_predicate_oracle: output_oracle,
        limit,
    };
    PredicateLimitCheck::<Fr, MvPCS, UvPCS>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;
    Ok(())
}
