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

use super::{InclusionCheckPIOP, InclusionCheckProverInput, InclusionCheckVerifierInput};

#[test]
fn inclusion_check_with_non_actv_is_complete() -> SnarkResult<()> {
    inclusion_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
    )?;

    inclusion_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([20, 7, 18, 20, 18, 2, 12, 3], Fr),
        None,
        3,
        to_field_vec!([65536, 7, 18, 20, 18, 2, 12, 3], Fr),
        None,
    )?;

    inclusion_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([20, 7, 18, 20], Fr),
        None,
        3,
        to_field_vec!([65536, 7, 18, 20, 18, 2, 12, 3], Fr),
        None,
    )?;

    Ok(())
}

#[test]
fn inclusion_check_is_complete() -> SnarkResult<()> {
    inclusion_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        Some(to_field_vec!([0, 1, 1, 1], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
    )?;

    inclusion_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 7, 200], Fr),
        Some(to_field_vec!([0, 0, 1, 0], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        Some(to_field_vec!([0, 1, 0, 1], Fr)),
    )?;

    inclusion_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([7, 7, 7, 200], Fr),
        Some(to_field_vec!([0, 1, 1, 0], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        Some(to_field_vec!([0, 1, 0, 1], Fr)),
    )?;

    Ok(())
}

#[test]
fn inclusion_check_with_non_actv_is_sound() -> SnarkResult<()> {
    inclusion_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 8, 2], Fr),
        None,
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
    )?;

    inclusion_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 10, 2], Fr),
        None,
        3,
        to_field_vec!([25, 7, 7, 2, 1, 5, 6, 123], Fr),
        None,
    )?;

    Ok(())
}

#[test]
fn inclusion_check_is_sound() -> SnarkResult<()> {
    inclusion_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 7, 9], Fr),
        Some(to_field_vec!([0, 1, 1, 1], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
    )?;

    inclusion_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([25, 7, 7, 9], Fr),
        Some(to_field_vec!([0, 1, 1, 1], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        Some(to_field_vec!([0, 1, 1, 1], Fr)),
    )?;

    Ok(())
}

fn inclusion_check_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    included_nv: usize,
    included_col_values: Vec<Fr>,
    included_col_actv_values: Option<Vec<Fr>>,
    super_nv: usize,
    super_col_values: Vec<Fr>,
    super_col_actv_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let err = inclusion_check_test_helper::<Fr, MvPCS, UvPCS>(
        included_nv,
        included_col_values,
        included_col_actv_values,
        super_nv,
        super_col_values,
        super_col_actv_values,
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

fn inclusion_check_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    included_nv: usize,
    included_col_values: Vec<Fr>,
    included_col_actv_values: Option<Vec<Fr>>,
    super_nv: usize,
    super_col_values: Vec<Fr>,
    super_col_actv_values: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;
    let included_col_tr_p = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
        included_nv,
        &included_col_values,
    ))?;
    let included_col_actv_tr_p = match included_col_actv_values {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(included_nv, &actv_values),
        )?),
        None => None,
    };

    let included_col = ArithCol::new(
        None,
        included_col_tr_p.clone(),
        included_col_actv_tr_p.clone(),
    );

    let super_col_tr_p = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(super_nv, &super_col_values))?;
    let super_col_actv_tr_p =
        match super_col_actv_values {
            Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
                &MLE::from_evaluations_slice(super_nv, &actv_values),
            )?),
            None => None,
        };

    let super_col = ArithCol::new(None, super_col_tr_p.clone(), super_col_actv_tr_p.clone());

    let inclusion_check_prover_input = InclusionCheckProverInput {
        included_col: included_col.clone(),
        super_col: super_col.clone(),
    };

    InclusionCheckPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, inclusion_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let included_col_comm = verifier.track_mv_com_by_id(included_col_tr_p.get_id())?;
    let included_col_actv_comm = match included_col_actv_tr_p {
        Some(actv_tr_p) => Some(verifier.track_mv_com_by_id(actv_tr_p.get_id())?),
        None => None,
    };
    let super_col_comm = verifier.track_mv_com_by_id(super_col_tr_p.get_id())?;
    let super_col_actv_comm = match super_col_actv_tr_p {
        Some(actv_tr_p) => Some(verifier.track_mv_com_by_id(actv_tr_p.get_id())?),
        None => None,
    };

    let included_col_comm = ColCom::new(
        included_col.get_data_type(),
        included_col_comm,
        included_col_actv_comm,
        included_col.get_num_vars(),
    );

    let super_col_comm = ColCom::new(
        super_col.get_data_type(),
        super_col_comm,
        super_col_actv_comm,
        super_col.get_num_vars(),
    );

    let inclusion_check_verifier_input = InclusionCheckVerifierInput {
        included_col_comm,
        super_col_comm,
    };

    InclusionCheckPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, inclusion_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
