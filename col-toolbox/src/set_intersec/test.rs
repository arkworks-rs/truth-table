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
use datafusion::physical_plan::values;

use crate::set_intersec::{
    SetInterUnionCheckPIOP, SetInterUnionProverInput, SetInterUnionVerifierInput,
};
// Test cases for multiplicity check, where the active and multiplicative
// columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn set_inter_union_check_is_complete() -> SnarkResult<()> {
    set_inter_union_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        3,
        4,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8], Fr),
        None,
        to_field_vec!([1, 2, 9, 10, 11, 12, 13, 14], Fr),
        None,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            Fr
        )),
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Fr
        )),
    )?;
    set_inter_union_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        2,
        4,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8], Fr),
        None,
        to_field_vec!([1, 9, 10, 11], Fr),
        None,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
            Fr
        )),
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Fr
        )),
    )?;
    set_inter_union_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        3,
        4,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8], Fr),
        Some(to_field_vec!([1, 0, 1, 1, 1, 1, 1, 1], Fr)),
        to_field_vec!([1, 2, 9, 10, 11, 12, 13, 14], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr)),
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            Fr
        )),
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Fr
        )),
    )?;
    Ok(())
}

#[test]
fn set_inter_union_check_is_sound() -> SnarkResult<()> {
    set_inter_union_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        3,
        4,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8], Fr),
        None,
        to_field_vec!([1, 2, 9, 10, 11, 12, 13, 14], Fr),
        None,
        to_field_vec!([1, 2, 3, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            Fr
        )),
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Fr
        )),
    )?;

    set_inter_union_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        3,
        4,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8], Fr),
        None,
        to_field_vec!([1, 2, 9, 10, 11, 12, 13, 14], Fr),
        None,
        to_field_vec!([1, 2, 3, 17, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            Fr
        )),
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Fr
        )),
    )?;

    set_inter_union_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        3,
        4,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8], Fr),
        None,
        to_field_vec!([1, 2, 9, 10, 11, 12, 13, 14], Fr),
        None,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0],
            Fr
        )),
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Fr
        )),
    )?;
    set_inter_union_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        3,
        4,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8], Fr),
        None,
        to_field_vec!([1, 2, 9, 10, 11, 12, 13, 14], Fr),
        None,
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
            Fr
        )),
        to_field_vec!([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], Fr),
        Some(to_field_vec!(
            [1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Fr
        )),
    )?;
    Ok(())
}

fn set_inter_union_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv_left: usize,
    nv_right: usize,
    nv_union_inter: usize,
    values_left: Vec<Fr>,
    actv_left: Option<Vec<Fr>>,
    values_right: Vec<Fr>,
    actv_right: Option<Vec<Fr>>,
    values_union: Vec<Fr>,
    actv_union: Option<Vec<Fr>>,
    values_inter: Vec<Fr>,
    actv_inter: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let err = set_inter_union_test_helper::<Fr, MvPCS, UvPCS>(
        nv_left,
        nv_right,
        nv_union_inter,
        values_left,
        actv_left,
        values_right,
        actv_right,
        values_union,
        actv_union,
        values_inter,
        actv_inter,
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

fn set_inter_union_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv_left: usize,
    nv_right: usize,
    nv_union_inter: usize,
    values_left: Vec<Fr>,
    actv_left: Option<Vec<Fr>>,
    values_right: Vec<Fr>,
    actv_right: Option<Vec<Fr>>,
    values_union: Vec<Fr>,
    actv_union: Option<Vec<Fr>>,
    values_inter: Vec<Fr>,
    actv_inter: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;
    // Left column preparation
    let values_left =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv_left, &values_left))?;
    let actv_left =
        match actv_left {
            Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
                &MLE::from_evaluations_slice(nv_left, &actv_values),
            )?),
            None => None,
        };
    // Right column preparation
    let values_right = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv_right, &values_right))?;
    let actv_right =
        match actv_right {
            Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
                &MLE::from_evaluations_slice(nv_right, &actv_values),
            )?),
            None => None,
        };
    // Intersection column preparation
    let values_inter = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
        nv_union_inter,
        &values_inter,
    ))?;
    let actv_inter = match actv_inter {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_union_inter, &actv_values),
        )?),
        None => None,
    };
    // Union column preparation
    let values_union = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
        nv_union_inter,
        &values_union,
    ))?;
    let actv_union = match actv_union {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_union_inter, &actv_values),
        )?),
        None => None,
    };
    let set_inter_union_check_prover_input = SetInterUnionProverInput {
        col_left: ArithCol::new(None, values_left, actv_left.clone()),
        col_right: ArithCol::new(None, values_right, actv_right.clone()),
        col_inter: ArithCol::new(None, values_inter, actv_inter.clone()),
        col_union: ArithCol::new(None, values_union, actv_union.clone()),
    };
    SetInterUnionCheckPIOP::<Fr, MvPCS, UvPCS>::prove(
        &mut prover,
        set_inter_union_check_prover_input,
    )?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let left_id = verifier.peek_next_id();
    let left_com = verifier.track_mv_com_by_id(left_id)?;

    let left_actv_com = match &actv_left {
        Some(_) => {
            let actv_id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(actv_id)?)
        },
        None => None,
    };
    let right_id = verifier.peek_next_id();
    let right_com = verifier.track_mv_com_by_id(right_id)?;

    let right_actv_com = match &actv_right {
        Some(_) => {
            let actv_id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(actv_id)?)
        },
        None => None,
    };
    let inter_id = verifier.peek_next_id();
    let inter_com = verifier.track_mv_com_by_id(inter_id)?;
    let inter_actv_com = match &actv_inter {
        Some(_) => {
            let actv_id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(actv_id)?)
        },
        None => None,
    };
    let union_id = verifier.peek_next_id();
    let union_com = verifier.track_mv_com_by_id(union_id)?;
    let union_actv_com = match &actv_union {
        Some(_) => {
            let actv_id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(actv_id)?)
        },
        None => None,
    };
    //////////////////////////////////////////////////////////////////////

    let set_inter_union_check_verifier_input = SetInterUnionVerifierInput {
        col_left: ColCom {
            inner: left_com,
            actv: left_actv_com,
            data_type: None,
            num_vars: nv_left,
        },
        col_right: ColCom {
            inner: right_com,
            actv: right_actv_com,
            data_type: None,
            num_vars: nv_right,
        },
        col_inter: ColCom {
            inner: inter_com,
            actv: inter_actv_com,
            data_type: None,
            num_vars: nv_union_inter,
        },
        col_union: ColCom {
            inner: union_com,
            actv: union_actv_com,
            data_type: None,
            num_vars: nv_union_inter,
        },
    };

    SetInterUnionCheckPIOP::<Fr, MvPCS, UvPCS>::verify(
        &mut verifier,
        set_inter_union_check_verifier_input,
    )?;
    verifier.verify()?;
    Ok(())
}
