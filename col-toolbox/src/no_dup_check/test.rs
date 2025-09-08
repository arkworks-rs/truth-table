use crate::no_dup_check::{NoDupCheckProverInput, NoDupCheckVerifierInput};

use super::NoDupPIOP;

use arithmetic::col::{ArithCol, ColCom};
use ark_ff::{Field, PrimeField};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
// Sets up randomized inputs for testing EqCheck
#[test]
fn nodup_check_is_complete() -> SnarkResult<()> {
    // All activated tests
    no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
        vec![Fr::ONE; 2_usize.pow(3_u32)],
    )?;
    no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([40, 7, 16, 20], Fr),
        vec![Fr::ONE; 2_usize.pow(2_u32)],
    )?;

    // Some activated tests
    no_dup_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
        to_field_vec!([1, 0, 0, 1, 0, 0, 1, 1], Fr),
    )?;

    // exit successfully
    Ok(())
}

#[test]
fn nodup_check_is_sound() -> SnarkResult<()> {
    binary_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([4, 7, 18, 20, 18, 2, 12, 3], Fr),
        vec![Fr::ONE; 2_usize.pow(3_u32)],
    )?;
    binary_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        2,
        to_field_vec!([20, 7, 16, 20], Fr),
        vec![Fr::ONE; 2_usize.pow(2_u32)],
    )?;

    binary_check_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([3, 7, 1, 20, 18, 2, 12, 3], Fr),
        to_field_vec!([1, 0, 0, 1, 0, 0, 1, 1], Fr),
    )?;

    // exit successfully
    Ok(())
}
fn binary_check_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    in_evals: Vec<Fr>,
    in_actv: Vec<Fr>,
) -> SnarkResult<()> {
    let err = no_dup_test_helper::<Fr, MvPCS, UvPCS>(nv, in_evals, in_actv).unwrap_err();

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

fn no_dup_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    in_evals: Vec<Fr>,
    in_actv: Vec<Fr>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;
    let in_mle = MLE::from_evaluations_vec(nv, in_evals);
    let in_tr_p = prover.track_and_commit_mat_mv_poly(&in_mle).unwrap();
    let in_actv_p = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(nv, in_actv))
        .unwrap();
    let col = ArithCol::new(None, in_tr_p.clone(), Some(in_actv_p.clone()));
    let no_dup_prover_input = NoDupCheckProverInput { col };
    NoDupPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, no_dup_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    let in_comm = verifier.track_mv_com_by_id(in_tr_p.id())?;
    let actvm = verifier.track_mv_com_by_id(in_actv_p.id())?;
    let col_comm = ColCom::new(None, in_comm, Some(actvm), nv);
    let no_dup_verifier_input = NoDupCheckVerifierInput { col_comm };
    NoDupPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, no_dup_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
