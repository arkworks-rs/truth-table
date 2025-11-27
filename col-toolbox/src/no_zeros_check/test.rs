use super::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput};
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult,
    pcs::PCS, piop::PIOP, test_utils::test_prelude, to_field_vec,
};
use ark_test_curves::bls12_381::Fr;
// Test cases for multiplicity check, where the active and multiplicative
// columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn nozeros_check_is_complete() -> SnarkResult<()> {
    nozero_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr)),
    )?;
    nozero_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([4, 7, 1, 20, 0, 2, 0, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 0, 1, 0, 1], Fr)),
    )?;
    Ok(())
}

#[test]
fn nozeros_check_is_sound() -> SnarkResult<()> {
    nozero_test_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([4, 7, 0, 20, 18, 2, 12, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr)),
    )?;
    nozero_test_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([4, 0, 1, 20, 0, 2, 0, 3], Fr),
        Some(to_field_vec!([1, 1, 1, 1, 0, 1, 0, 1], Fr)),
    )?;
    Ok(())
}

fn nozero_test_soundness_helper<B: SnarkBackend>(
    nv: usize,
    values: Vec<B::F>,
    activator_values: Option<Vec<B::F>>,
) -> SnarkResult<()> {
    let err = nozero_test_helper::<B>(nv, values, activator_values).unwrap_err();

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

fn nozero_test_helper<B: SnarkBackend>(
    nv: usize,
    values: Vec<B::F>,
    activator_values: Option<Vec<B::F>>,
) -> SnarkResult<()> {
    // Ensure tracing subscriber is initialized once for test output

    let (mut prover, mut verifier) = test_prelude::<B>()?;
    let inner = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &values))?;
    let activator =
        match activator_values {
            Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
                &MLE::from_evaluations_slice(nv, &activator_values),
            )?),
            None => None,
        };
    let activator_clone = activator.clone();
    let no_zero_check_prover_input = NoZerosCheckProverInput {
        col: TrackedCol::new(inner, activator_clone, None),
    };
    NoZerosCheck::<B>::prove(&mut prover, no_zero_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let inner_id = verifier.peek_next_id();
    let inner_com = verifier.track_mv_com_by_id(inner_id)?;
    let activator_com = match &activator {
        Some(_) => {
            let activator_id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(activator_id)?)
        }
        None => None,
    };
    let no_zero_check_verifier_input = NoZerosCheckVerifierInput {
        tracked_col_oracle: TrackedColOracle::new(inner_com, activator_com, None),
    };

    NoZerosCheck::<B>::verify(&mut verifier, no_zero_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
