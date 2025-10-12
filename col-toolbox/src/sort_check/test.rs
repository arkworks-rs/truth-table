// use arithmetic::col::{TrackedCol, TrackedColOracle};
// use ark_ff::{Field, PrimeField};
// use ark_piop::{
//     arithmetic::mat_poly::{lde::LDE, mle::MLE},
//     errors::SnarkResult,
//     pcs::{PCS, kzg10::KZG10, pst13::PST13},
//     piop::PIOP,
//     test_utils::test_prelude,
//     to_field_vec,
// };
// use ark_std::{
//     rand::{RngCore, SeedableRng},
//     test_rng,
// };
// use ark_test_curves::bls12_381::{Bls12_381, Fr};

// use super::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput};
// // Sets up randomized inputs for testing EqCheck
// #[test]
// fn perm_check_is_complete() -> SnarkResult<()> {
//     // All activated tests
//     perm_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
//         3,
//         to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
//         vec![Fr::ONE; 2_usize.pow(3_u32)],
//         3,
//         to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
//         vec![Fr::ONE; 2_usize.pow(3_u32)],
//     )?;

//     perm_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
//         3,
//         to_field_vec!([1, 7, 4, 20, 18, 3, 12, 2], Fr),
//         vec![Fr::ONE; 2_usize.pow(3_u32)],
//         3,
//         to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
//         vec![Fr::ONE; 2_usize.pow(3_u32)],
//     )?;

//     perm_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
//         3,
//         to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
//         to_field_vec!([1, 0, 0, 1, 0, 0, 1, 1], Fr),
//         2,
//         to_field_vec!([12, 3, 4, 20], Fr),
//         to_field_vec!([1, 1, 1, 1], Fr),
//     )?;
//     perm_check_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
//         3,
//         to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr),
//         to_field_vec!([0, 0, 0, 1, 0, 0, 1, 1], Fr),
//         2,
//         to_field_vec!([12, 3, 4, 20], Fr),
//         to_field_vec!([1, 1, 0, 1], Fr),
//     )?;

//     Ok(())
// }

// #[test]
// fn perm_check_is_sound() -> SnarkResult<()> {
//     permcheck_test_soundness_helper::<Fr, PST13<Bls12_381>,
// KZG10<Bls12_381>>(         3,
//         to_field_vec!([1, 7, 4, 20, 18, 3, 12, 2], Fr),
//         vec![Fr::ONE; 2_usize.pow(3_u32)],
//         3,
//         to_field_vec!([4, 8, 1, 20, 18, 2, 12, 3], Fr),
//         vec![Fr::ONE; 2_usize.pow(3_u32)],
//     )?;

//     permcheck_test_soundness_helper::<Fr, PST13<Bls12_381>,
// KZG10<Bls12_381>>(         3,
//         to_field_vec!([4, 7, 1, 20, 18, 2, 12, 9], Fr),
//         to_field_vec!([1, 0, 0, 1, 0, 0, 1, 1], Fr),
//         2,
//         to_field_vec!([12, 2, 4, 20], Fr),
//         to_field_vec!([1, 1, 1, 1], Fr),
//     )?;

//     Ok(())
// }

// fn permcheck_test_soundness_helper<
//     Fr: PrimeField,
//     MvPCS: PCS<Fr, Poly = MLE<Fr>>,
//     UvPCS: PCS<Fr, Poly = LDE<Fr>>,
// >(
//     left_nv: usize,
//     left_evals: Vec<Fr>,
//     left_activator: Vec<Fr>,
//     right_nv: usize,
//     right_evals: Vec<Fr>,
//     right_activator: Vec<Fr>,
// ) -> SnarkResult<()> {
//     let err = perm_check_test_helper::<Fr, MvPCS, UvPCS>(
//         left_nv,
//         left_evals,
//         left_activator,
//         right_nv,
//         right_evals,
//         right_activator,
//     )
//     .unwrap_err();
//     #[cfg(feature = "honest-prover")]
//     {
//         assert!(matches!(
//             err,
//             ark_piop::errors::SnarkError::ProverError(
//                 ark_piop::prover::errors::ProverError::HonestProverError(
//                     ark_piop::prover::errors::HonestProverError::FalseClaim
//                 )
//             )
//         ));
//     }

//     #[cfg(not(feature = "honest-prover"))]
//     {
//         assert!(matches!(
//             err,
//             ark_piop::errors::SnarkError::VerifierError(
//
// ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(_)
// )         ));
//     }

//     Ok(())
// }

// fn perm_check_test_helper<
//     Fr: PrimeField,
//     MvPCS: PCS<Fr, Poly = MLE<Fr>>,
//     UvPCS: PCS<Fr, Poly = LDE<Fr>>,
// >(
//     left_nv: usize,
//     left_evals: Vec<Fr>,
//     left_activator: Vec<Fr>,
//     right_nv: usize,
//     right_evals: Vec<Fr>,
//     right_activator: Vec<Fr>,
// ) -> SnarkResult<()> {
//     let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

//     /////////////////////////////////////////////////
//     let left_mle = MLE::from_evaluations_vec(left_nv, left_evals);
//     let left_tr_p = prover.track_and_commit_mat_mv_poly(&left_mle).unwrap();
//     let left_activator_p = prover
//         .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(left_nv,
// left_activator))         .unwrap();
//     let left_col = TrackedCol::new(None, left_tr_p.clone(),
// Some(left_activator_p.clone()));
// ///////////////////////////////////////////// ////////     let right_mle =
// MLE::from_evaluations_vec(right_nv, right_evals);     let right_tr_p =
// prover.track_and_commit_mat_mv_poly(&right_mle).unwrap();
//     let right_activator_p = prover
//         .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(right_nv,
// right_activator))         .unwrap();
//     let right_col = TrackedCol::new(None, right_tr_p.clone(),
// Some(right_activator_p.clone()));

//     /////////////////////////////////////////////////////////

//     let perm_piop_prover_input = PermPIOPProverInput {
//         left_col,
//         right_col,
//     };

//     PermPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover,
// perm_piop_prover_input)?;     let proof = prover.build_proof()?;
//     verifier.set_proof(proof);
//     let left_comm = verifier.track_mv_com_by_id(left_tr_p.id())?;
//     let left_activatorm =
// verifier.track_mv_com_by_id(left_activator_p.id())?;
//     let left_tracked_col_oracle = TrackedColOracle::new(None, left_comm,
// Some(left_activatorm), left_nv);

//     let right_comm = verifier.track_mv_com_by_id(right_tr_p.id())?;
//     let right_activatorm =
// verifier.track_mv_com_by_id(right_activator_p.id())?;
//     let right_tracked_col_oracle = TrackedColOracle::new(None, right_comm,
// Some(right_activatorm), right_nv);     let perm_piop_verifier_input =
// PermPIOPVerifierInput {         left_tracked_col_oracle,
//         right_tracked_col_oracle,
//     };
//     PermPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier,
// perm_piop_verifier_input)?;     verifier.verify()?;
//     Ok(())
// }
