//! A tool to defragment a column by removing the non-activated elements
use std::marker::PhantomData;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};
use ark_std::log2;
use num_bigint::BigUint;

use crate::perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput};

/// A tool to defragment a column by removing the non-activated rows and
/// reducing the size of the underlying polynomial (as much as possible). It
/// internally invokes the permutation-check to ensure that the defragmented
/// column is still consistent with the original column.
pub struct Defragmenter<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> Defragmenter<F, MvPCS, UvPCS>
where
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    F: PrimeField,
{
    pub fn defrag_col(
        tracker: &mut Prover<F, MvPCS, UvPCS>,
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<TrackedCol<F, MvPCS, UvPCS>> {
        if col.activator_tracked_poly().is_none() {
            return Ok(col.clone());
        }
        let new_col_size_f: F = col
            .activator_tracked_poly()
            .as_ref()
            .unwrap()
            .evaluations()
            .iter()
            .sum();
        let new_col_size_biguint: BigUint = new_col_size_f.into();
        let new_col_size: usize = new_col_size_biguint.try_into().unwrap();
        let new_nv: usize = log2(new_col_size) as usize;
        // if new_nv == old_nv {
        //     return Ok(col.clone());
        // }

        let mut new_activator_evals: Vec<F> = Vec::with_capacity(1 << new_nv);
        let mut new_inner_evals: Vec<F> = Vec::with_capacity(1 << new_nv);
        col.data_tracked_poly()
            .evaluations()
            .iter()
            .zip(
                col.activator_tracked_poly()
                    .as_ref()
                    .unwrap()
                    .evaluations()
                    .iter(),
            )
            .for_each(|(val, activator)| {
                if activator.is_one() {
                    new_activator_evals.push(F::one());
                    new_inner_evals.push(*val);
                }
            });
        new_activator_evals.resize(1 << new_nv, F::zero());
        new_inner_evals.resize(1 << new_nv, F::zero());
        let new_col = TrackedCol::new(
            tracker.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                new_nv,
                new_inner_evals,
            ))?,
            Some(
                tracker.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                    new_nv,
                    new_activator_evals,
                ))?,
            ),
            col.field_ref(),
        );

        let perm_piop_prover_input = PermPIOPProverInput {
            left_col: col.clone(),
            right_col: new_col.clone(),
        };

        PermPIOP::<F, MvPCS, UvPCS>::prove(tracker, perm_piop_prover_input)?;
        Ok(new_col)
    }

    pub fn defrag_tracked_col_oracle(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<TrackedColOracle<F, MvPCS, UvPCS>> {
        if tracked_col_oracle.activator_tracked_oracle().is_none() {
            return Ok(tracked_col_oracle.clone());
        }

        let new_col_inner_id = verifier.peek_next_id();
        let new_col_inner_tr = verifier.track_mv_com_by_id(new_col_inner_id)?;
        let new_col_activator_id = verifier.peek_next_id();
        let new_col_activator_tr = verifier.track_mv_com_by_id(new_col_activator_id)?;

        let new_tracked_col_oracle = TrackedColOracle::new(
            new_col_inner_tr.clone(),
            Some(new_col_activator_tr),
            tracked_col_oracle.field_ref().clone(),
        );

        let perm_piop_verifier_input = PermPIOPVerifierInput {
            left_tracked_col_oracle: tracked_col_oracle.clone(),
            right_tracked_col_oracle: new_tracked_col_oracle.clone(),
        };

        PermPIOP::<F, MvPCS, UvPCS>::verify(verifier, perm_piop_verifier_input)?;
        Ok(new_tracked_col_oracle)
    }
}
