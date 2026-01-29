use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult,
    piop::PIOP, test_utils::test_prelude, to_field_vec,
};

use super::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput};
// Test cases for multiplicity check, where the active and multiplicative
// columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn binary_check_is_complete() -> SnarkResult<()> {
    binary_check_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], <ark_piop::DefaultSnarkBackend as ark_piop::SnarkBackend>::F),
    )?;
    binary_check_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([1, 0, 1, 1, 1, 0, 0, 1], <ark_piop::DefaultSnarkBackend as ark_piop::SnarkBackend>::F),
    )?;
    binary_check_test_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([0, 0, 0, 0, 0, 0, 0, 0,], <ark_piop::DefaultSnarkBackend as ark_piop::SnarkBackend>::F),
    )?;
    Ok(())
}

#[test]
fn binary_check_is_sound() -> SnarkResult<()> {
    binary_check_test_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([4, 7, 0, 20, 18, 2, 12, 3], <ark_piop::DefaultSnarkBackend as ark_piop::SnarkBackend>::F),
    )?;
    binary_check_test_soundness_helper::<DefaultSnarkBackend>(
        3,
        to_field_vec!([4, 0, 1, 20, 0, 2, 0, 3], <ark_piop::DefaultSnarkBackend as ark_piop::SnarkBackend>::F),
    )?;
    Ok(())
}

fn binary_check_test_soundness_helper<B: SnarkBackend>(
    nv: usize,
    activator_values: Vec<B::F>,
) -> SnarkResult<()> {
    let err = binary_check_test_helper::<B>(nv, activator_values).unwrap_err();

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

fn binary_check_test_helper<B: SnarkBackend>(
    nv: usize,
    activator_values: Vec<B::F>,
) -> SnarkResult<()> {
    // Ensure tracing subscriber is initialized once for test output
    let (mut prover, mut verifier) = test_prelude::<B>()?;
    let activator =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &activator_values))?;
    let activator_clone = activator.clone();
    let binary_check_prover_input = BinaryCheckProverInput {
        predicate: activator_clone,
    };
    BinaryCheckPIOP::<B>::prove(&mut prover, binary_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let activator_id = verifier.peek_next_id();
    let activator = verifier.track_mv_com_by_id(activator_id)?;
    let binary_check_verifier_input = BinaryCheckVerifierInput {
        predicate_oracle: activator,
    };

    BinaryCheckPIOP::<B>::verify(&mut verifier, binary_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
