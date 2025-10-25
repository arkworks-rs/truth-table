use ark_ff::{One, PrimeField, Zero};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_piop::verifier::structs::oracle::InnerOracle;
use ark_test_curves::bls12_381::{Bls12_381, Fr};

use super::{
    shift_permutation_mle, shift_permutation_oracle, PrescribedPermutationPIOP,
    PrescribedPermutationPIOPProverInput, PrescribedPermutationPIOPVerifierInput,
};

#[test]
fn prescribed_permutation_is_complete() -> SnarkResult<()> {
    prescribed_permutation_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 2, 3, 4], Fr),
        to_field_vec!([3, 1, 4, 2], Fr),
        to_field_vec!([1, 3, 0, 2], Fr),
    )?;

    prescribed_permutation_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([10, 10, 20, 20], Fr),
        to_field_vec!([20, 10, 10, 20], Fr),
        to_field_vec!([1, 2, 0, 3], Fr),
    )?;

    prescribed_permutation_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([9, 11], Fr),
        to_field_vec!([11, 9], Fr),
        to_field_vec!([1, 0], Fr),
    )?;


    Ok(())
}

#[test]
fn prescribed_permutation_is_sound() -> SnarkResult<()> {
    prescribed_permutation_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 2, 3, 4], Fr),
        to_field_vec!([3, 1, 2, 4], Fr),
        to_field_vec!([1, 3, 0, 2], Fr),
    )?;

    prescribed_permutation_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([5, 6, 7, 8], Fr),
        to_field_vec!([7, 5, 6, 8], Fr),
        to_field_vec!([1, 1, 2, 3], Fr),
    )?;

    prescribed_permutation_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([9, 11], Fr),
        to_field_vec!([11, 9], Fr),
        to_field_vec!([1, 2], Fr),
    )?;

    prescribed_permutation_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        to_field_vec!([1, 2, 3, 4], Fr),
        to_field_vec!([4, 3, 2, 1], Fr),
        to_field_vec!([3, 2, 2, 1], Fr),
    )?;

    Ok(())
}

#[test]
fn shift_permutation_oracle_boolean_hypercube() -> SnarkResult<()> {
    let log_size = 3usize;
    let shift = 1usize;
    let right = true;

    let oracle = shift_permutation_oracle::<Fr>(log_size, shift, right);
    let expected = shift_permutation_mle::<Fr>(log_size, shift, right).evaluations();
    match oracle.inner() {
        InnerOracle::Multivariate(eval_fn) => {
            for idx in 0..(1 << log_size) {
                let point: Vec<Fr> = (0..log_size)
                    .map(|bit| {
                        if (idx >> bit) & 1 == 1 {
                            Fr::one()
                        } else {
                            Fr::zero()
                        }
                    })
                    .collect();
                let value = eval_fn(point.clone()).expect("oracle evaluation");
                assert_eq!(value, expected[idx]);
            }
        },
        _ => panic!("shift_permutation_oracle should be multivariate"),
    }

    Ok(())
}

fn prescribed_permutation_test_helper<
    Fr: PrimeField,
   MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    left_vals: Vec<Fr>,
    right_vals: Vec<Fr>,
    permutation_vals: Vec<Fr>,
) -> SnarkResult<()> {
    assert!(left_vals.len().is_power_of_two());
    assert_eq!(left_vals.len(), right_vals.len());
    assert_eq!(left_vals.len(), permutation_vals.len());

    let log_size = left_vals.len().trailing_zeros() as usize;
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    let left_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, left_vals))?;
    let right_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, right_vals))?;
    let permutation_poly = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, permutation_vals))?;

    let prover_input = PrescribedPermutationPIOPProverInput {
        left_tracked_poly: left_poly.clone(),
        right_tracked_poly: right_poly.clone(),
        permutation_tracked_poly: permutation_poly.clone(),
    };
    PrescribedPermutationPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, prover_input)?;

    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let left_oracle = verifier.track_mv_com_by_id(left_poly.id())?;
    let right_oracle = verifier.track_mv_com_by_id(right_poly.id())?;
    let permutation_oracle = verifier.track_mv_com_by_id(permutation_poly.id())?;

    let verifier_input = PrescribedPermutationPIOPVerifierInput {
        left_tracked_oracle: left_oracle,
        right_tracked_oracle: right_oracle,
        permutation_tracked_oracle: permutation_oracle,
    };
    PrescribedPermutationPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, verifier_input)?;
    verifier.verify()?;

    Ok(())
}

fn prescribed_permutation_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    left_vals: Vec<Fr>,
    right_vals: Vec<Fr>,
    permutation_vals: Vec<Fr>,
) -> SnarkResult<()> {
    let err = prescribed_permutation_test_helper::<Fr, MvPCS, UvPCS>(
        left_vals,
        right_vals,
        permutation_vals,
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
