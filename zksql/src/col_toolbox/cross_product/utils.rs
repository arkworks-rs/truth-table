use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use crate::PolynomialCommitmentScheme;
use crate::tracker::prelude::*;

pub fn front_alias_tracked_poly<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    poly: &TrackedPoly<F, PCS>,
    added_nv: usize,
) -> TrackedPoly<F, PCS> {
    let poly_nv = poly.num_vars();
    let res_nv = poly_nv + added_nv;
    let poly_evals = poly.evaluations();
    let poly_len = poly_evals.len();
    let chunk_len = 2_usize.pow(added_nv as u32);
    let mut res_evals = Vec::<F>::with_capacity(poly_len);

    for i in 0..poly_len {
        for _ in 0..chunk_len {
            res_evals.push(poly_evals[i]);
        }
    }
    let res_mle = DenseMultilinearExtension::from_evaluations_vec(res_nv, res_evals);
    let res_poly = prover_tracker.track_mat_poly(res_mle);
    res_poly
}

pub fn back_alias_tracked_poly<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    poly: &TrackedPoly<F, PCS>,
    added_nv: usize,
) -> TrackedPoly<F, PCS> {
    let poly_nv = poly.num_vars();
    let res_nv = poly_nv + added_nv;
    let poly_evals = poly.evaluations();
    let poly_len = poly_evals.len();
    let num_rotations = 2_usize.pow(added_nv as u32);
    let mut res_evals = Vec::<F>::with_capacity(poly_len);

    for _ in 0..num_rotations {
        for i in 0..poly_len {
            res_evals.push(poly_evals[i]);
        }
    }
    let res_mle = DenseMultilinearExtension::from_evaluations_vec(res_nv, res_evals);
    let res_poly = prover_tracker.track_mat_poly(res_mle);
    res_poly
}

// // put new vars at the front of comm evals (making values repeat in chunks)
// pub fn front_alias_tracked_comm<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
//     verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
//     comm: &TrackedComm<F, PCS>,
//     comm_nv: usize,
//     added_nv: usize,
// ) -> TrackedComm<F, PCS> {
//     let res_comm_closure = move |pt: &[F]| -> Result<F, PolyIOPErrors> {
//         let truncated_pt = &pt[added_nv..];
//         let eval = comm.eval_virtual_comm(truncated_pt).unwrap();
//         Ok(eval)
//     };
//     let boxed_closure = Box::new(res_comm_closure);
//     let res_col_comm = verifier_tracker.track_virtual_comm(boxed_closure);
//     res_col_comm
// }

// pub fn back_alias_tracked_comm<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
//     verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
//     comm: &TrackedComm<F, PCS>,
//     comm_nv: usize,
//     added_nv: usize,
// ) -> TrackedComm<F, PCS> {
//     let res_comm_closure = move |pt: &[F]| -> Result<F, PolyIOPErrors> {
//         let truncated_pt = &pt[..comm_nv];
//         let eval = comm.eval_virtual_comm(truncated_pt).unwrap();
//         Ok(eval)
//     };
//     let boxed_closure = Box::new(res_comm_closure);
//     let res_col_comm = verifier_tracker.track_virtual_comm(boxed_closure);
//     res_col_comm
// }