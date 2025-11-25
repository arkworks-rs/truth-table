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

use super::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput};
// Test cases for multiplicity check, where the active and multiplicative
// columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn binary_check_is_complete() -> SnarkResult<()> {
    binary_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
    )?;
    binary_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 0, 1, 1, 1, 0, 0, 1], Fr),
    )?;
    binary_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([0, 0, 0, 0, 0, 0, 0, 0,], Fr),
    )?;
    Ok(())
}

#[test]
fn binary_check_is_sound() -> SnarkResult<()> {
    binary_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 7, 0, 20, 18, 2, 12, 3], Fr),
    )?;
    binary_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 0, 1, 20, 0, 2, 0, 3], Fr),
    )?;
    Ok(())
}

fn binary_check_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>> + 'static + Send + Sync,
    UvPCS: PCS<Fr, Poly = LDE<Fr>> + 'static + Send + Sync,
>(
    nv: usize,
    activator_values: Vec<Fr>,
) -> SnarkResult<()> {
    let err = binary_check_test_helper::<Fr, MvPCS, UvPCS>(nv, activator_values).unwrap_err();

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

fn binary_check_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>> + 'static + Send + Sync,
    UvPCS: PCS<Fr, Poly = LDE<Fr>> + 'static + Send + Sync,
>(
    nv: usize,
    activator_values: Vec<Fr>,
) -> SnarkResult<()> {
    // Ensure tracing subscriber is initialized once for test output
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;
    let activator =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &activator_values))?;
    let activator_clone = activator.clone();
    let binary_check_prover_input = BinaryCheckProverInput {
        predicate: activator_clone,
    };
    BinaryCheckPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, binary_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let activator_id = verifier.peek_next_id();
    let activator = verifier.track_mv_com_by_id(activator_id)?;
    let binary_check_verifier_input = BinaryCheckVerifierInput {
        predicate_oracle: activator,
    };

    BinaryCheckPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, binary_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
