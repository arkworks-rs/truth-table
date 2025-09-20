use super::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput};
use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
// Test cases for multiplicity check, where the active and multiplicative
// columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn nozeros_check_is_complete() -> SnarkResult<()> {
    nozero_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr)),
    )?;
    nozero_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 7, 1, 20, 0, 2, 0, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 0, 1, 0, 1], Fr)),
    )?;
    Ok(())
}

#[test]
fn nozeros_check_is_sound() -> SnarkResult<()> {
    nozero_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 7, 0, 20, 18, 2, 12, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr)),
    )?;
    nozero_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 0, 1, 20, 0, 2, 0, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 0, 1, 0, 1], Fr)),
    )?;
    Ok(())
}

fn nozero_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    values: Vec<Fr>,
    actv_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let err = nozero_test_helper::<Fr, MvPCS, UvPCS>(nv, values, actv_values).unwrap_err();

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

fn nozero_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    values: Vec<Fr>,
    actv_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    // Ensure tracing subscriber is initialized once for test output

    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;
    let inner = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &values))?;
    let actv = match actv_values {
        Some(actv_values) => Some(
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &actv_values))?,
        ),
        None => None,
    };
    let actv_clone = actv.clone();
    let no_zero_check_prover_input = NoZerosCheckProverInput {
        col: ArithCol::new(None, inner, actv_clone),
    };
    NoZerosCheck::<Fr, MvPCS, UvPCS>::prove(&mut prover, no_zero_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let inner_id = verifier.peek_next_id();
    let inner_com = verifier.track_mv_com_by_id(inner_id)?;
    let actv_com = match &actv {
        Some(_) => {
            let actv_id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(actv_id)?)
        },
        None => None,
    };
    let no_zero_check_verifier_input = NoZerosCheckVerifierInput {
        col_comm: ColCom {
            inner: inner_com,
            actv: actv_com,
            data_type: None,
            num_vars: nv,
        },
    };

    NoZerosCheck::<Fr, MvPCS, UvPCS>::verify(&mut verifier, no_zero_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
