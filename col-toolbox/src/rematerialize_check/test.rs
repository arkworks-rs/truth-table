use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::Fr;

use crate::rematerialize_check::{
    RematerializeCheck, RematerializeCheckProverInput, RematerializeCheckVerifierInput,
};

#[test]
fn rematerialize_is_complete() -> SnarkResult<()> {
    rematerialize_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 80], Fr),
        Some(to_field_vec!([1, 1, 1, 1], Fr)),
    )?;

    rematerialize_test_helper::<DefaultSnarkBackend>(
        2,
        to_field_vec!([5, 15, 25, 35], Fr),
        None,
        2,
        to_field_vec!([5, 15, 25, 35], Fr),
        Some(to_field_vec!([1, 1, 1, 1], Fr)),
    )?;

    rematerialize_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 80], Fr),
        None,
    )?;

    Ok(())
}

#[test]
fn rematerialize_is_sound() -> SnarkResult<()> {
    rematerialize_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 80], Fr),
        Some(to_field_vec!([1, 2, 1, 0], Fr)),
    )?;

    rematerialize_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 99], Fr),
        Some(to_field_vec!([1, 1, 1, 1], Fr)),
    )?;

    rematerialize_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        None,
        2,
        to_field_vec!([10, 30, 60, 80], Fr),
        Some(to_field_vec!([1, 1, 1, 1], Fr)),
    )?;

    rematerialize_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 99], Fr),
        None,
    )?;

    Ok(())
}

fn rematerialize_test_helper<B: SnarkBackend>(
    input_nv: usize,
    input_vals: Vec<B::F>,
    input_activator: Option<Vec<B::F>>,
    output_nv: usize,
    output_vals: Vec<B::F>,
    output_activator: Option<Vec<B::F>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<B>()?;

    let input_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(input_nv, input_vals))?;
    let input_activator_poly = match input_activator {
        Some(vals) => {
            Some(prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(input_nv, vals))?)
        }
        None => None,
    };
    let input_col = TrackedCol::new(input_poly.clone(), input_activator_poly.clone(), None);

    let output_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(output_nv, output_vals))?;
    let output_activator_poly = match output_activator {
        Some(vals) => {
            Some(prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(output_nv, vals))?)
        }
        None => None,
    };
    let output_col = TrackedCol::new(output_poly.clone(), output_activator_poly.clone(), None);

    let prover_input = RematerializeCheckProverInput {
        input_tracked_col: input_col,
        output_tracked_col: output_col,
    };
    RematerializeCheck::<B>::prove(&mut prover, prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let input_oracle = {
        let data_oracle = verifier.track_mv_com_by_id(input_poly.id())?;
        let activator_oracle = match input_activator_poly {
            Some(ref poly) => Some(verifier.track_mv_com_by_id(poly.id())?),
            None => None,
        };
        TrackedColOracle::new(data_oracle, activator_oracle, None)
    };

    let output_oracle = {
        let data_oracle = verifier.track_mv_com_by_id(output_poly.id())?;
        let activator_oracle = match output_activator_poly {
            Some(ref poly) => Some(verifier.track_mv_com_by_id(poly.id())?),
            None => None,
        };
        TrackedColOracle::new(data_oracle, activator_oracle, None)
    };

    let verifier_input = RematerializeCheckVerifierInput {
        input_tracked_col_oracle: input_oracle,
        output_tracked_col_oracle: output_oracle,
    };
    RematerializeCheck::<B>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;
    Ok(())
}

fn rematerialize_soundness_helper<B: SnarkBackend>(
    input_nv: usize,
    input_vals: Vec<B::F>,
    input_activator: Option<Vec<B::F>>,
    output_nv: usize,
    output_vals: Vec<B::F>,
    output_activator: Option<Vec<B::F>>,
) -> SnarkResult<()> {
    let err = rematerialize_test_helper::<B>(
        input_nv,
        input_vals,
        input_activator,
        output_nv,
        output_vals,
        output_activator,
    )
    .unwrap_err();

    #[cfg(feature = "honest-prover")]
    {
        assert!(matches!(
            err,
            SnarkError::ProverError(ark_piop::prover::errors::ProverError::HonestProverError(
                ark_piop::prover::errors::HonestProverError::FalseClaim
            ))
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        assert!(matches!(
            err,
            SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(_)
            )
        ));
    }

    Ok(())
}
