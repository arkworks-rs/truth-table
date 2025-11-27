use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult,
    pcs::PCS, piop::PIOP, test_utils::test_prelude, to_field_vec,
};
use ark_test_curves::bls12_381::Fr;

use super::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput};

#[test]
fn supp_check_with_non_activator_is_complete() -> SnarkResult<()> {
    supp_check_test_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 9, 2], Fr),
        None,
        2,
        to_field_vec!([25, 9, 7, 2], Fr),
        None,
    )?;

    supp_check_test_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 7, 7], Fr),
        None,
        1,
        to_field_vec!([25, 7], Fr),
        None,
    )?;

    supp_check_test_helper::<DefaultSnarkBackend>(
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
    supp_check_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([7, 2, 3, 3, 2, 6, 6, 7], Fr),
        None,
        3,
        to_field_vec!([7, 6, 6, 5, 1, 2, 2, 3], Fr),
        Some(to_field_vec!([1, 1, 0, 0, 0, 0, 1, 1], Fr)),
    )?;

    supp_check_test_helper::<DefaultSnarkBackend>(
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
fn supp_check_with_non_activator_is_sound() -> SnarkResult<()> {
    supp_check_test_soundness_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 9, 2], Fr),
        None,
        2,
        to_field_vec!([25, 9, 6, 2], Fr),
        None,
    )?;

    supp_check_test_soundness_helper::<DefaultSnarkBackend>(
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
    supp_check_test_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([7, 2, 3, 3, 2, 6, 6, 7], Fr),
        None,
        3,
        to_field_vec!([7, 6, 6, 5, 1, 2, 2, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 0, 0, 0, 1, 1], Fr)),
    )?;

    supp_check_test_soundness_helper::<DefaultSnarkBackend>(
        1,
        to_field_vec!([1, 2], Fr),
        None,
        3,
        to_field_vec!([7, 6, 6, 5, 1, 2, 2, 3], Fr),
        Some(to_field_vec!([1, 0, 0, 0, 1, 0, 1, 0], Fr)),
    )?;
    Ok(())
}

fn supp_check_test_soundness_helper<B: SnarkBackend>(
    nv: usize,
    col_values: Vec<B::F>,
    col_activator_values: Option<Vec<B::F>>,
    supp_nv: usize,
    supp_col_values: Vec<B::F>,
    supp_col_activator_values: Option<Vec<B::F>>,
) -> SnarkResult<()> {
    let err = supp_check_test_helper::<B>(
        nv,
        col_values,
        col_activator_values,
        supp_nv,
        supp_col_values,
        supp_col_activator_values,
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

fn supp_check_test_helper<B: SnarkBackend>(
    nv: usize,
    col_values: Vec<B::F>,
    col_activator_values: Option<Vec<B::F>>,
    supp_nv: usize,
    supp_col_values: Vec<B::F>,
    supp_col_activator_values: Option<Vec<B::F>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<B>()?;
    let col_tr_p =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &col_values))?;
    let col_activator_tr_p =
        match col_activator_values {
            Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
                &MLE::from_evaluations_slice(nv, &activator_values),
            )?),
            None => None,
        };

    let col = TrackedCol::new(col_tr_p.clone(), col_activator_tr_p.clone(), None);

    let supp_col_tr_p = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(supp_nv, &supp_col_values))?;
    let supp_col_activator_tr_p = match supp_col_activator_values {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(supp_nv, &activator_values),
        )?),
        None => None,
    };

    let supp_col = TrackedCol::new(supp_col_tr_p.clone(), supp_col_activator_tr_p.clone(), None);

    let supp_check_prover_input = SuppCheckProverInput {
        col: col.clone(),
        supp: supp_col.clone(),
    };

    SuppCheckPIOP::<B>::prove(&mut prover, supp_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let tracked_col_oracle = verifier.track_mv_com_by_id(col_tr_p.id())?;
    let col_activator_comm = match col_activator_tr_p {
        Some(activator_tr_p) => Some(verifier.track_mv_com_by_id(activator_tr_p.id())?),
        None => None,
    };
    let supp_tracked_col_oracle = verifier.track_mv_com_by_id(supp_col_tr_p.id())?;
    let supp_col_activator_comm = match supp_col_activator_tr_p {
        Some(activator_tr_p) => Some(verifier.track_mv_com_by_id(activator_tr_p.id())?),
        None => None,
    };

    let tracked_col_oracle =
        TrackedColOracle::new(tracked_col_oracle, col_activator_comm, col.field_ref());

    let supp_tracked_col_oracle = TrackedColOracle::new(
        supp_tracked_col_oracle,
        supp_col_activator_comm,
        supp_col.field_ref(),
    );

    let supp_check_verifier_input = SuppCheckVerifierInput {
        col: tracked_col_oracle,
        supp: supp_tracked_col_oracle,
    };

    SuppCheckPIOP::<B>::verify(&mut verifier, supp_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
