use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
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
use datafusion::arrow::datatypes::{DataType, Field};
use std::sync::Arc;

use super::{SortCheck, SortCheckProverInput, SortCheckVerifierInput};

#[test]
fn sort_check_none_actv_is_complete() -> SnarkResult<()> {
    sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 2, 3, 4], Fr),
        None,
        DataType::UInt64,
        true,
        true,
    )?;

    sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 1, 2, 2], Fr),
        None,
        DataType::UInt64,
        true,
        false,
    )?;

    sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([4, 3, 2, 1], Fr),
        None,
        DataType::UInt64,
        false,
        true,
    )?;

    sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([4, 4, 2, 2], Fr),
        None,
        DataType::Int32,
        false,
        false,
    )?;

    Ok(())
}

#[test]
fn sort_check_with_actv_is_complete() -> SnarkResult<()> {
    sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 6, 4, 2, 3, 20, 18, 9], Fr),
        Some(to_field_vec!([1, 0, 0, 1, 1, 0, 0, 1], Fr)),
        DataType::UInt32,
        true,
        true,
    )?;

    sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 6, 4, 2, 2, 20, 18, 9], Fr),
        Some(to_field_vec!([1, 0, 0, 1, 1, 0, 0, 1], Fr)),
        DataType::UInt32,
        true,
        false,
    )?;
    sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([100,2,4,80,70,85,90,50], Fr),
        Some(to_field_vec!([1, 0, 0, 1, 1, 0, 0, 1], Fr)),
        DataType::UInt32,
        false,
        true,
    )?;
        sort_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([100,2,4,80,70,85,90,70], Fr),
        Some(to_field_vec!([1, 0, 0, 1, 1, 0, 0, 1], Fr)),
        DataType::UInt32,
        false,
        false,
    )?;
    Ok(())
}

#[test]
fn sort_check_is_sound() -> SnarkResult<()> {
    sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([3, 1, 2, 4], Fr),
        None,
        DataType::Int16,
        true,
        true,
    )?;

    sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 1, 2, 0], Fr),
        None,
        DataType::Boolean,
        false,
        true,
    )?;

    sort_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 3, 2, 0, 0, 0, 0, 0], Fr),
        Some(to_field_vec!([1, 1, 1, 0, 0, 0, 0, 0], Fr)),
        DataType::Utf8,
        true,
        true,
    )?;

    Ok(())
}

fn sort_check_test_helper<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    data_evals: Vec<F>,
    activator_evals: Option<Vec<F>>,
    data_type: DataType,
    ascending: bool,
    strict: bool,
) -> SnarkResult<()> {
    assert!(data_evals.len().is_power_of_two());
    let log_size = data_evals.len().trailing_zeros() as usize;

    let (mut prover, mut verifier) = test_prelude::<F, MvPCS, UvPCS>()?;
    let field_ref = Arc::new(Field::new("sort_col", data_type.clone(), false));

    let data_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, data_evals))?;
    let activator_poly = match activator_evals {
        Some(vals) => {
            Some(prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, vals))?)
        },
        None => None,
    };

    let tracked_col = TrackedCol::new(
        data_poly.clone(),
        activator_poly.clone(),
        Some(field_ref.clone()),
    );

    let prover_input = SortCheckProverInput {
        tracked_col,
        ascending,
        strict,
    };
    SortCheck::<F, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let data_oracle = verifier.track_mv_com_by_id(data_poly.id())?;
    let activator_oracle = match activator_poly {
        Some(poly) => Some(verifier.track_mv_com_by_id(poly.id())?),
        None => None,
    };
    let tracked_col_oracle = TrackedColOracle::new(data_oracle, activator_oracle, Some(field_ref));

    let verifier_input = SortCheckVerifierInput {
        tracked_col_oracle,
        ascending,
        strict,
    };
    SortCheck::<F, MvPCS, UvPCS>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;

    Ok(())
}

fn sort_check_soundness_helper<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    data_evals: Vec<F>,
    activator_evals: Option<Vec<F>>,
    data_type: DataType,
    ascending: bool,
    strict: bool,
) -> SnarkResult<()> {
    let err = sort_check_test_helper::<F, MvPCS, UvPCS>(
        data_evals,
        activator_evals,
        data_type,
        ascending,
        strict,
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
