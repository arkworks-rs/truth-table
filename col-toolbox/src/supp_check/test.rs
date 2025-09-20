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

use super::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput};

#[test]
fn supp_check_with_non_actv_is_complete() -> SnarkResult<()> {
    supp_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 9, 2], Fr),
        None,
        2,
        to_field_vec!([25, 9, 7, 2], Fr),
        None,
    )?;

    supp_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 7, 7], Fr),
        None,
        1,
        to_field_vec!([25, 7], Fr),
        None,
    )?;

    supp_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([7, 2, 3, 3, 2, 6, 6, 7], Fr),
        None,
        2,
        to_field_vec!([7, 6, 2, 3], Fr),
        None,
    )?;

    Ok(())
}

#[test]
fn supp_check_is_complete() -> SnarkResult<()> {
    supp_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([7, 2, 3, 3, 2, 6, 6, 7], Fr),
        None,
        3,
        to_field_vec!([7, 6, 6, 5, 1, 2, 2, 3], Fr),
        Some(to_field_vec!([1, 1, 0, 0, 0, 0, 1, 1], Fr)),
    )?;

    supp_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        1,
        to_field_vec!([1, 2], Fr),
        None,
        3,
        to_field_vec!([7, 6, 6, 5, 1, 2, 2, 3], Fr),
        Some(to_field_vec!([0, 0, 0, 0, 1, 0, 1, 0], Fr)),
    )?;
    Ok(())
}

#[test]
fn supp_check_with_non_actv_is_sound() -> SnarkResult<()> {
    supp_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 9, 2], Fr),
        None,
        2,
        to_field_vec!([25, 9, 6, 2], Fr),
        None,
    )?;

    supp_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 7, 7], Fr),
        None,
        1,
        to_field_vec!([24, 7], Fr),
        None,
    )?;

    Ok(())
}

#[test]
fn supp_check_is_sound() -> SnarkResult<()> {
    supp_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([7, 2, 3, 3, 2, 6, 6, 7], Fr),
        None,
        3,
        to_field_vec!([7, 6, 6, 5, 1, 2, 2, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 0, 0, 0, 1, 1], Fr)),
    )?;

    supp_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        1,
        to_field_vec!([1, 2], Fr),
        None,
        3,
        to_field_vec!([7, 6, 6, 5, 1, 2, 2, 3], Fr),
        Some(to_field_vec!([1, 0, 0, 0, 1, 0, 1, 0], Fr)),
    )?;
    Ok(())
}

fn supp_check_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    col_values: Vec<Fr>,
    col_actv_values: Option<Vec<Fr>>,
    supp_nv: usize,
    supp_col_values: Vec<Fr>,
    supp_col_actv_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let err = supp_check_test_helper::<Fr, MvPCS, UvPCS>(
        nv,
        col_values,
        col_actv_values,
        supp_nv,
        supp_col_values,
        supp_col_actv_values,
    )
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

fn supp_check_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    col_values: Vec<Fr>,
    col_actv_values: Option<Vec<Fr>>,
    supp_nv: usize,
    supp_col_values: Vec<Fr>,
    supp_col_actv_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;
    let col_tr_p =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &col_values))?;
    let col_actv_tr_p = match col_actv_values {
        Some(actv_values) => Some(
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &actv_values))?,
        ),
        None => None,
    };

    let col = ArithCol::new(None, col_tr_p.clone(), col_actv_tr_p.clone());

    let supp_col_tr_p = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(supp_nv, &supp_col_values))?;
    let supp_col_actv_tr_p =
        match supp_col_actv_values {
            Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
                &MLE::from_evaluations_slice(supp_nv, &actv_values),
            )?),
            None => None,
        };

    let supp_col = ArithCol::new(None, supp_col_tr_p.clone(), supp_col_actv_tr_p.clone());

    let supp_check_prover_input = SuppCheckProverInput {
        col: col.clone(),
        supp: supp_col.clone(),
    };

    SuppCheckPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, supp_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let col_comm = verifier.track_mv_com_by_id(col_tr_p.id())?;
    let col_actv_comm = match col_actv_tr_p {
        Some(actv_tr_p) => Some(verifier.track_mv_com_by_id(actv_tr_p.id())?),
        None => None,
    };
    let supp_col_comm = verifier.track_mv_com_by_id(supp_col_tr_p.id())?;
    let supp_col_actv_comm = match supp_col_actv_tr_p {
        Some(actv_tr_p) => Some(verifier.track_mv_com_by_id(actv_tr_p.id())?),
        None => None,
    };

    let col_comm = ColCom::new(col.data_type(), col_comm, col_actv_comm, col.num_vars());

    let supp_col_comm = ColCom::new(
        supp_col.data_type(),
        supp_col_comm,
        supp_col_actv_comm,
        supp_col.num_vars(),
    );

    let supp_check_verifier_input = SuppCheckVerifierInput {
        col: col_comm,
        supp: supp_col_comm,
    };

    SuppCheckPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, supp_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
