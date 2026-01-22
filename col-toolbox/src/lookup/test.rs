use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult,
    piop::PIOP, test_utils::test_prelude, to_field_vec,
};
use ark_test_curves::bls12_381::Fr;

use super::{LookupPIOP, LookupProverInput, LookupVerifierInput};

#[test]
fn lookup_with_non_activator_is_complete() -> SnarkResult<()> {
    lookup_test_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
    )?;

    lookup_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([20, 7, 18, 20, 18, 2, 12, 3], Fr),
        None,
        3,
        to_field_vec!([65536, 7, 18, 20, 18, 2, 12, 3], Fr),
        None,
    )?;

    lookup_test_helper::<DefaultSnarkBackend>(
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
fn lookup_is_complete() -> SnarkResult<()> {
    lookup_test_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        Some(to_field_vec!([0, 1, 1, 1], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
    )?;

    lookup_test_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 7, 200], Fr),
        Some(to_field_vec!([0, 0, 1, 0], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        Some(to_field_vec!([0, 1, 0, 1], Fr)),
    )?;

    lookup_test_helper::<DefaultSnarkBackend>(
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
fn lookup_with_non_activator_is_sound() -> SnarkResult<()> {
    lookup_test_soundness_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 8, 2], Fr),
        None,
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
    )?;

    lookup_test_soundness_helper::<DefaultSnarkBackend>(
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
fn lookup_is_sound() -> SnarkResult<()> {
    lookup_test_soundness_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 7, 9], Fr),
        Some(to_field_vec!([0, 1, 1, 1], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        None,
    )?;

    lookup_test_soundness_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([25, 7, 7, 9], Fr),
        Some(to_field_vec!([0, 1, 1, 1], Fr)),
        2,
        to_field_vec!([25, 7, 7, 2], Fr),
        Some(to_field_vec!([0, 1, 1, 1], Fr)),
    )?;

    Ok(())
}

fn lookup_test_soundness_helper<B: SnarkBackend>(
    included_nv: usize,
    included_col_values: Vec<B::F>,
    included_col_activator_values: Option<Vec<B::F>>,
    super_nv: usize,
    super_col_values: Vec<B::F>,
    super_col_activator_values: Option<Vec<B::F>>,
) -> SnarkResult<()> {
    let err = lookup_test_helper::<B>(
        included_nv,
        included_col_values,
        included_col_activator_values,
        super_nv,
        super_col_values,
        super_col_activator_values,
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

fn lookup_test_helper<B: SnarkBackend>(
    included_nv: usize,
    included_col_values: Vec<B::F>,
    included_col_activator_values: Option<Vec<B::F>>,
    super_nv: usize,
    super_col_values: Vec<B::F>,
    super_col_activator_values: Option<Vec<B::F>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<B>()?;
    let included_col_tr_p = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
        included_nv,
        &included_col_values,
    ))?;
    let included_col_activator_tr_p = match included_col_activator_values {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(included_nv, &activator_values),
        )?),
        None => None,
    };

    let included_col = TrackedCol::new(
        included_col_tr_p.clone(),
        included_col_activator_tr_p.clone(),
        None,
    );

    let super_col_tr_p = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(super_nv, &super_col_values))?;
    let super_col_activator_tr_p = match super_col_activator_values {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(super_nv, &activator_values),
        )?),
        None => None,
    };

    let super_col = TrackedCol::new(
        super_col_tr_p.clone(),
        super_col_activator_tr_p.clone(),
        None,
    );

    let lookup_prover_input = LookupProverInput {
        included_cols: vec![included_col.clone()],
        super_col: super_col.clone(),
    };

    LookupPIOP::<B>::prove(&mut prover, lookup_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let included_tracked_col_oracle = verifier.track_mv_com_by_id(included_col_tr_p.id())?;
    let included_col_activator_comm = match included_col_activator_tr_p {
        Some(activator_tr_p) => Some(verifier.track_mv_com_by_id(activator_tr_p.id())?),
        None => None,
    };
    let super_tracked_col_oracle = verifier.track_mv_com_by_id(super_col_tr_p.id())?;
    let super_col_activator_comm = match super_col_activator_tr_p {
        Some(activator_tr_p) => Some(verifier.track_mv_com_by_id(activator_tr_p.id())?),
        None => None,
    };

    let included_tracked_col_oracle = TrackedColOracle::new(
        included_tracked_col_oracle,
        included_col_activator_comm,
        included_col.field_ref(),
    );

    let super_tracked_col_oracle = TrackedColOracle::new(
        super_tracked_col_oracle,
        super_col_activator_comm,
        super_col.field_ref(),
    );

    let lookup_verifier_input = LookupVerifierInput {
        included_tracked_col_oracles: vec![included_tracked_col_oracle],
        super_tracked_col_oracle,
    };

    LookupPIOP::<B>::verify(&mut verifier, lookup_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
