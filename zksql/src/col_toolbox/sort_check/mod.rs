#[cfg(test)]
mod test;

use arithmetic::{ark_ff, ark_poly};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_std::{One, Zero};
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use kit::ark_std;
use std::marker::PhantomData;

use crate::{
    col_toolbox::{
        inclusion_check::InclusionCheck, no_zeros_check::NoZerosCheck,
        prescr_perm_check::PrescrPermPIOP,
    },
    tracker::prelude::*,
};
use ark_poly::Polynomial;
pub struct StrictSortPIOP<F: Field + PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

// TODO: Add a PIOP for sort which is not strict
// TODO: Add descending and ascending options

// A PIOP to prove a column is strictly sorted
// by showing it's elements are a subset of [0, 2^n]
// and the product of its elements is non-zero
// This code as written only proves that the col is strictly sorted ascending.
// To prove descending or non-strict requires edits
impl<F: Field + PrimeField, PCS: PolynomialCommitmentScheme<F>> StrictSortPIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F: PrimeField,
{
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        sorted_col: &Col<F, PCS>,
        range_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // retrieve some useful values from the inputs
        let range_poly = range_col.inner_poly.clone();
        let sorted_poly_evals = sorted_col.inner_poly.evaluations();
        let sorted_nv = sorted_col.num_vars();
        let sorted_len = sorted_poly_evals.len();
        let range_nv = range_poly.num_vars;
        let range_len = 2_usize.pow(range_nv as u32);
        let p_poly = sorted_col.inner_poly.clone();
        let p_sel = sorted_col.actv_poly.clone();

        // create shifted permutation poly for the prescribed permutation check, which
        // shows q is correctly created based off of p. Then we can use q for
        // calculating diffs in the range check 	    create first vector s=(0,
        // 1, .., 2^{nv}-1) and another that is the permuted version of it t=(1, ..,
        // 2^{nv}-1, 0) 	    (p,q) are p is orig input, q is p left shifted by 1
        // with wraparound
        let mut shift_perm_evals: Vec<F> = Vec::<F>::with_capacity(sorted_len);
        shift_perm_evals.extend((1..(sorted_len)).map(|x| F::from(x as u64)));
        shift_perm_evals.push(F::zero());

        let mut q_evals = Vec::<F>::with_capacity(sorted_len);
        q_evals.extend_from_slice(&sorted_poly_evals[1..sorted_len]);
        q_evals.push(*sorted_poly_evals.first().unwrap());

        // Create a difference poly and its selector for the range check, which shows
        // the col is sorted since the differences are in the correct range
        //      sorted_col = [a_0, a_1, ..] from the input
        //      selector = [1, .., 1, 1, 0]
        //      diff_evals = [selector * (q - p) + (1 - selector)]
        // recall (1 - selector) = [0, 0, .., 0, 1]. Adding it makes the last element of
        // diff_evals non-zero git so we can pass the NoZerosCheck check for
        // strictness
        let mut diff_range_sel_evals = vec![F::one(); sorted_len];
        diff_range_sel_evals[sorted_len - 1] = F::zero(); // the last element is allowed to be out of range because of the wraparound
        let diff_evals = (0..sorted_len)
            .map(
                |i| {
                    diff_range_sel_evals[i] * (q_evals[i] - sorted_poly_evals[i])
                        + (F::one() - diff_range_sel_evals[i])
                }, // p-q here made the sign correct? depends on sort order?
            )
            .collect::<Vec<_>>();
        let diff_range_sel_mle =
            DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_range_sel_evals);

        // Set up the tracker and prove the prescribed permutation check
        let one_mle =
            DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![F::one(); sorted_len]);
        let shift_perm_mle =
            DenseMultilinearExtension::from_evaluations_vec(sorted_nv, shift_perm_evals);
        let q_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, q_evals);
        let one_poly = prover_tracker.track_mat_poly(one_mle);
        let shift_perm_poly = prover_tracker.track_mat_poly(shift_perm_mle); // note: is a precomputed poly
        let q_poly = prover_tracker.track_and_commit_poly(q_mle)?; // is also precomputed??
        let q_col = Col::new(q_poly.clone(), one_poly.clone());
        PrescrPermPIOP::<F, PCS>::prove(
            prover_tracker,
            &sorted_col.clone(),
            &q_col.clone(),
            &shift_perm_poly.clone(),
        )?;

        // Set up the tracker and prove the range/inclusion check
        let diff_range_sel = prover_tracker.track_mat_poly(diff_range_sel_mle); // note: is a precomputed one-poly
        let diff_range_poly = diff_range_sel
            .mul_poly(&q_poly.sub_poly(&p_poly))
            .add_scalar(F::one())
            .sub_poly(&diff_range_sel);
        #[cfg(debug_assertions)]
        {
            assert_eq!(diff_range_poly.evaluations(), diff_evals);
        }
        let diff_range_col = Col::new(diff_range_poly.clone(), diff_range_sel.clone());
        let range_sel_mle =
            DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![F::one(); range_len]);
        let range_sel = prover_tracker.track_mat_poly(range_sel_mle); // note: is a precomputedone-poly
        let range_col = Col::new(range_poly.clone(), range_sel);
        InclusionCheck::<F, PCS>::prove(
            prover_tracker,
            &diff_range_col.clone(),
            &range_col.clone(),
        )?;

        // prove diff contains no zeros
        // TODO: make this an optional check. Sometimes we don't care about strictness
        let dups_check_col = Col::new(diff_range_poly.clone(), p_sel.clone()); // use p_sel instead of diff_range_sel to ignore stuff
        dbg!(dups_check_col.inner_poly.evaluations());
        dbg!(p_sel.evaluations());
        NoZerosCheck::<F, PCS>::prove(prover_tracker, &dups_check_col)?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        sorted_col_comm: &ColComm<F, PCS>,
        range_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let sorted_nv = sorted_col_comm.num_vars();
        let sorted_len = 2_usize.pow(sorted_nv as u32);
        let range_nv = range_col.num_vars();
        let range_comm = range_col.poly.clone();

        // set up closures specified in the IOP
        let p_comm = sorted_col_comm.poly.clone();

        let mut shift_perm_evals: Vec<F> = Vec::<F>::with_capacity(sorted_len);
        shift_perm_evals.extend((1..(sorted_len)).map(|x| F::from(x as u64)));
        shift_perm_evals.push(F::zero());
        let shift_perm_mle =
            DenseMultilinearExtension::from_evaluations_vec(sorted_nv, shift_perm_evals);
        let shift_perm_closure = move |pt: &[F]| -> Result<
            F,
            // TODO: Change to_vec
            PolyIOPErrors,
        > { Ok(shift_perm_mle.evaluate(&pt.to_vec())) };

        let mut diff_sel_evals = vec![F::one(); sorted_len];
        diff_sel_evals[sorted_len - 1] = F::zero();
        let diff_sel_mle =
            DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_sel_evals);
        let diff_sel_closure =
            move |pt: &[F]| -> Result<F, PolyIOPErrors> { Ok(diff_sel_mle.evaluate(&pt.to_vec())) };

        let one_closure = |_: &[F]| -> Result<F, PolyIOPErrors> { Ok(F::one()) };

        // set up the tracker and verify the prescribed permutation check
        let one_comm = verifier_tracker.track_virtual_comm(Box::new(one_closure));
        let shift_perm_comm = verifier_tracker.track_virtual_comm(Box::new(shift_perm_closure));
        let q_poly_id = verifier_tracker.get_next_id();
        let q_comm = verifier_tracker.transfer_prover_comm(q_poly_id);
        let q_col = ColComm::new(q_comm.clone(), one_comm.clone(), sorted_nv);
        PrescrPermPIOP::<F, PCS>::verify(
            verifier_tracker,
            &sorted_col_comm.clone(),
            &q_col.clone(),
            &shift_perm_comm.clone(),
        )?;

        // set up the tracker and verify the range check
        let diff_sel_comm = verifier_tracker.track_virtual_comm(Box::new(diff_sel_closure));
        let diff_comm = diff_sel_comm
            .mul_comms(&q_comm.sub_comms(&p_comm))
            .add_scalar(F::one())
            .sub_comms(&diff_sel_comm);
        let diff_col = ColComm::new(diff_comm.clone(), diff_sel_comm, sorted_nv);
        let range_sel_closure = one_closure.clone();
        let range_sel = verifier_tracker.track_virtual_comm(Box::new(range_sel_closure));
        let range_col = ColComm::new(range_comm.clone(), range_sel, range_nv);
        InclusionCheck::<F, PCS>::verify(verifier_tracker, &diff_col.clone(), &range_col.clone())?;

        // check that diff * diff_inverse - 1 = 0, showing that diff contains no zeros
        // and thus p has no dups
        let no_dups_check_col = ColComm::new(
            diff_comm.clone(),
            sorted_col_comm.selector.clone(),
            sorted_nv,
        );
        NoZerosCheck::<F, PCS>::verify(verifier_tracker, &no_dups_check_col)?;

        Ok(())
    }
}
