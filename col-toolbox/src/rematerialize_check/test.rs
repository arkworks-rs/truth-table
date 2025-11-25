use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};

use crate::rematerialize_check::{
    RematerializeCheck, RematerializeCheckProverInput, RematerializeCheckVerifierInput,
};

#[test]
fn rematerialize_is_complete() -> SnarkResult<()> {
    rematerialize_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 80], Fr),
        Some(to_field_vec!([1, 1, 1, 1], Fr)),
    )?;

    rematerialize_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([5, 15, 25, 35], Fr),
        None,
        2,
        to_field_vec!([5, 15, 25, 35], Fr),
        Some(to_field_vec!([1, 1, 1, 1], Fr)),
    )?;

    rematerialize_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
    rematerialize_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 80], Fr),
        Some(to_field_vec!([1, 2, 1, 0], Fr)),
    )?;

    rematerialize_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 99], Fr),
        Some(to_field_vec!([1, 1, 1, 1], Fr)),
    )?;

    rematerialize_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        None,
        2,
        to_field_vec!([10, 30, 60, 80], Fr),
        Some(to_field_vec!([1, 1, 1, 1], Fr)),
    )?;

    rematerialize_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([10, 20, 30, 40, 50, 60, 70, 80], Fr),
        Some(to_field_vec!([1, 0, 1, 0, 0, 1, 0, 1], Fr)),
        2,
        to_field_vec!([10, 30, 60, 99], Fr),
        None,
    )?;

    Ok(())
}

fn rematerialize_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>> + 'static + Send + Sync,
    UvPCS: PCS<Fr, Poly = LDE<Fr>> + 'static + Send + Sync,
>(
    input_nv: usize,
    input_vals: Vec<Fr>,
    input_activator: Option<Vec<Fr>>,
    output_nv: usize,
    output_vals: Vec<Fr>,
    output_activator: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

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
    RematerializeCheck::<Fr, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;
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
    RematerializeCheck::<Fr, MvPCS, UvPCS>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;
    Ok(())
}

fn rematerialize_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>> + 'static + Send + Sync,
    UvPCS: PCS<Fr, Poly = LDE<Fr>> + 'static + Send + Sync,
>(
    input_nv: usize,
    input_vals: Vec<Fr>,
    input_activator: Option<Vec<Fr>>,
    output_nv: usize,
    output_vals: Vec<Fr>,
    output_activator: Option<Vec<Fr>>,
) -> SnarkResult<()> {
    let err = rematerialize_test_helper::<Fr, MvPCS, UvPCS>(
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
