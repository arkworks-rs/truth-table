use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult,
    pcs::PCS, piop::PIOP, prover::structs::polynomial::TrackedPoly, test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::Fr;

use super::{OrCheckPIOP, OrCheckProverInput, OrCheckVerifierInput};
// Test cases for multiplicity check, where the active and multiplicative
// columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn or_check_is_complete() -> SnarkResult<()> {
    or_check_test_helper::<DefaultSnarkBackend>(
        3,
        vec![
            to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
            to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        ],
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
    )?;
    or_check_test_helper::<DefaultSnarkBackend>(
        3,
        vec![
            to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr),
            to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr),
        ],
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
    )?;
    or_check_test_helper::<DefaultSnarkBackend>(
        3,
        vec![
            to_field_vec!([0, 1, 0, 0, 0, 0, 0, 0], Fr),
            to_field_vec!([1, 0, 1, 0, 1, 1, 1, 1], Fr),
        ],
        to_field_vec!([1, 1, 1, 0, 1, 1, 1, 1], Fr),
    )?;
    Ok(())
}

#[test]
fn or_check_is_sound() -> SnarkResult<()> {
    or_check_test_soundness_helper::<DefaultSnarkBackend>(
        3,
        vec![
            to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr),
            to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        ],
        to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr),
    )?;

    Ok(())
}

fn or_check_test_soundness_helper<B: SnarkBackend>(
    nv: usize,
    in_values: Vec<Vec<B::F>>,
    res_values: Vec<B::F>,
) -> SnarkResult<()> {
    let err = or_check_test_helper::<B>(nv, in_values, res_values).unwrap_err();

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

fn or_check_test_helper<B: SnarkBackend>(
    nv: usize,
    in_values: Vec<Vec<B::F>>,
    res_values: Vec<B::F>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<B>()?;
    let res_activator_tracked_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, &res_values))?;
    let in_activator_tracked_polys: Vec<TrackedPoly<B>> = in_values
        .iter()
        .map(|in_evals| {
            prover
                .track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv, in_evals))
                .unwrap()
        })
        .collect();
    let or_check_prover_input = OrCheckProverInput {
        in_activator_tracked_polys: in_activator_tracked_polys.clone(),
        res_activator_tracked_poly,
    };
    OrCheckPIOP::<B>::prove(&mut prover, or_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let activator_id = verifier.peek_next_id();
    let res_activator_orcl = verifier.track_mv_com_by_id(activator_id)?;
    let in_activator_orcls = in_activator_tracked_polys
        .iter()
        .map(|activator_tracked_poly| {
            verifier
                .track_mv_com_by_id(activator_tracked_poly.id())
                .unwrap()
        })
        .collect();
    let or_check_verifier_input = OrCheckVerifierInput {
        in_activator_orcls,
        res_activator_orcl,
    };

    OrCheckPIOP::<B>::verify(&mut verifier, or_check_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
