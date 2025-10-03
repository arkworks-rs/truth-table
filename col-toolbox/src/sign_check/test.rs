use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use datafusion::arrow::datatypes::DataType;

use super::{Sign, SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput};

use ark_ff::PrimeField;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
#[test]
fn uint8_non_negative_check_is_complete() -> SnarkResult<()> {
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([25, 7, 0, 2], Fr),
        None,
        Sign::NoneNegative,
    )?;

    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([-25, 7, 7, 0], Fr),
        Some(&to_field_vec!([0, 1, 1, 1], Fr)),
        Sign::NoneNegative,
    )?;

    Ok(())
}
#[test]
fn uint8_non_negative_check_is_sound() -> SnarkResult<()> {
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([-10, 7, 7, 2], Fr),
        None,
        Sign::NoneNegative,
    )?;

    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([10, 7, 7, 300], Fr),
        None,
        Sign::NoneNegative,
    )?;

    Ok(())
}

#[test]
fn int8_non_negative_check_is_complete() -> SnarkResult<()> {
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::Int8),
        2,
        &to_field_vec!([126, 7, 0, 2], Fr),
        None,
        Sign::NoneNegative,
    )?;

    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::Int8),
        2,
        &to_field_vec!([-25, 7, 7, 127], Fr),
        Some(&to_field_vec!([0, 1, 1, 1], Fr)),
        Sign::NoneNegative,
    )?;

    Ok(())
}
#[test]
fn int8_non_negative_check_is_sound() -> SnarkResult<()> {
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::Int8),
        2,
        &to_field_vec!([-10, 7, 7, 2], Fr),
        None,
        Sign::NoneNegative,
    )?;
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::Int8),
        2,
        &to_field_vec!([10, 7, 7, 128], Fr),
        None,
        Sign::NoneNegative,
    )?;

    Ok(())
}

#[test]
fn uint16_non_negative_check_is_complete() -> SnarkResult<()> {
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt16),
        2,
        &to_field_vec!([0, 7, 18, 20], Fr),
        None,
        Sign::NoneNegative,
    )?;
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt16),
        2,
        &to_field_vec!([-25, 7, 7, 127], Fr),
        Some(&to_field_vec!([0, 1, 1, 1], Fr)),
        Sign::NoneNegative,
    )?;
    Ok(())
}

#[test]
fn uint16_non_negative_check_is_sound() -> SnarkResult<()> {
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt16),
        2,
        &to_field_vec!([-10, 7, 18, 20], Fr),
        None,
        Sign::NoneNegative,
    )?;
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt16),
        2,
        &to_field_vec!([65537, 7, 18, 20], Fr),
        None,
        Sign::NoneNegative,
    )?;
    Ok(())
}

#[test]
fn uint32_non_negative_check_is_complete() -> SnarkResult<()> {
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt32),
        2,
        &to_field_vec!([25, 7, 0, 2], Fr),
        None,
        Sign::NoneNegative,
    )?;

    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt32),
        2,
        &to_field_vec!([-25, 7, 7, 0], Fr),
        Some(&to_field_vec!([0, 1, 1, 1], Fr)),
        Sign::NoneNegative,
    )?;

    Ok(())
}
#[test]
fn uint32_non_negative_check_is_sound() -> SnarkResult<()> {
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt32),
        2,
        &to_field_vec!([-4, 7, 0, 2], Fr),
        None,
        Sign::NoneNegative,
    )?;

    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt32),
        2,
        &to_field_vec!([-25, 7, 7, i64::MAX], Fr),
        None,
        Sign::NoneNegative,
    )?;

    Ok(())
}

#[test]
fn int32_non_negative_check_is_complete() -> SnarkResult<()> {
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::Int32),
        2,
        &to_field_vec!([i32::MAX, 7, 0, 2], Fr),
        None,
        Sign::NoneNegative,
    )?;

    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::Int32),
        2,
        &to_field_vec!([-25, 7, 7, 0], Fr),
        Some(&to_field_vec!([0, 1, 1, 1], Fr)),
        Sign::NoneNegative,
    )?;

    Ok(())
}

#[test]
fn int32_non_negative_check_is_sound() -> SnarkResult<()> {
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::Int32),
        2,
        &to_field_vec!([-4, 7, 0, 2], Fr),
        None,
        Sign::NoneNegative,
    )?;

    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::Int32),
        2,
        &to_field_vec!([-25, 7, 7, i64::MAX], Fr),
        None,
        Sign::NoneNegative,
    )?;

    Ok(())
}

#[test]
fn positive_check_is_complete() -> SnarkResult<()> {
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([25, 7, 7, 2], Fr),
        None,
        Sign::Positive,
    )?;

    Ok(())
}

#[test]
fn positive_check_is_sound() -> SnarkResult<()> {
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([25, 0, 7, 2], Fr),
        None,
        Sign::Positive,
    )?;

    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([25, 0, 7, -2], Fr),
        None,
        Sign::Positive,
    )?;

    Ok(())
}

#[test]
fn non_positive_check_is_complete() -> SnarkResult<()> {
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([-1, -7, -7, -2], Fr),
        None,
        Sign::NonePositive,
    )?;

    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([-1, 0, -7, -2], Fr),
        None,
        Sign::NonePositive,
    )?;

    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt16),
        3,
        &to_field_vec!([-71, -7, -18, -20, -10, -2, -12, -3], Fr),
        None,
        Sign::NonePositive,
    )?;
    Ok(())
}

#[test]
fn non_positive_check_is_sound() -> SnarkResult<()> {
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([-1, 7, -7, -2], Fr),
        None,
        Sign::NonePositive,
    )?;
    Ok(())
}

#[test]
fn negative_check_is_complete() -> SnarkResult<()> {
    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([-1, -7, -7, -2], Fr),
        None,
        Sign::Negative,
    )?;

    sign_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt16),
        3,
        &to_field_vec!([-71, -12, -18, -20, -10, -2, -12, -3], Fr),
        None,
        Sign::Negative,
    )?;

    Ok(())
}

#[test]
fn negative_check_is_sound() -> SnarkResult<()> {
    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt8),
        2,
        &to_field_vec!([0, -7, -7, -2], Fr),
        None,
        Sign::Negative,
    )?;

    sign_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        Some(DataType::UInt16),
        3,
        &to_field_vec!([-71, 10, -18, -20, -10, -2, -12, -3], Fr),
        None,
        Sign::Negative,
    )?;

    Ok(())
}
fn sign_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    data_type: Option<DataType>,
    num_vars: usize,
    in_vars: &[Fr],
    in_actv: Option<&[Fr]>,
    sign: Sign,
) -> SnarkResult<()> {
    let err = sign_test_helper::<Fr, MvPCS, UvPCS>(data_type, num_vars, in_vars, in_actv, sign)
        .unwrap_err();

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

fn sign_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    data_type: Option<DataType>,
    num_vars: usize,
    in_vars: &[Fr],
    in_actv: Option<&[Fr]>,
    sign: Sign,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    let in_tr_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(num_vars, in_vars))?;
    let in_actv_tr_poly = match in_actv {
        Some(actv) => Some(
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(num_vars, actv))?,
        ),
        None => None,
    };
    let in_col = TrackedCol::new(data_type.clone(), in_tr_poly.clone(), in_actv_tr_poly);
    let non_neg_prover_input = SignCheckProverInput {
        col: in_col.clone(),
        sign,
    };
    SignCheckPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, non_neg_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    let in_comm = verifier.track_mv_com_by_id(in_tr_poly.id())?;
    let actvm = in_col
        .actvtr_poly()
        .as_ref()
        .map(|actv| verifier.track_mv_com_by_id(actv.id()).unwrap());
    let in_comm = TrackedColOracle::new(data_type, in_comm, actvm, in_col.num_vars());
    let no_neg_verifier_input = SignCheckVerifierInput {
        tracked_col_oracle: in_comm,
        sign,
    };
    SignCheckPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, no_neg_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
