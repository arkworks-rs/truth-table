//! A tool to defragment a column by removing the non-activated elements
use std::marker::PhantomData;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult, piop::PIOP,
    prover::ArgProver, verifier::ArgVerifier,
};
use ark_std::log2;

use ark_ff::One;
use ark_ff::Zero;

use crate::irs::nodes::utils::nodup::rematerialize_check::RematerializeCheck;
use crate::irs::nodes::utils::nodup::rematerialize_check::RematerializeCheckProverInput;
use crate::irs::nodes::utils::nodup::rematerialize_check::RematerializeCheckVerifierInput;
/// A tool to defragment a column by removing the non-activated rows and
/// reducing the size of the underlying polynomial (as much as possible). It
/// internally invokes the permutation-check to ensure that the defragmented
/// column is still consistent with the original column.
pub struct Defragmenter<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

impl<B: SnarkBackend> Defragmenter<B> {
    pub fn defrag_col(
        tracker: &mut ArgProver<B>,
        col: &TrackedCol<B>,
    ) -> SnarkResult<TrackedCol<B>> {
        if col.activator_tracked_poly().is_none() {
            return Ok(col.clone());
        }
        let new_col_size: usize = col
            .activator_tracked_poly()
            .as_ref()
            .unwrap()
            .evaluations()
            .iter()
            .filter(|value| !value.is_zero())
            .count();
        let new_nv: usize = if new_col_size == 0 {
            // Avoid log2(0) by pinning the defragmented column to size 1.
            0
        } else {
            log2(new_col_size) as usize
        };
        // if new_nv == old_nv {
        //     return Ok(col.clone());
        // }

        let mut new_activator_evals: Vec<B::F> = Vec::with_capacity(1 << new_nv);
        let mut new_inner_evals: Vec<B::F> = Vec::with_capacity(1 << new_nv);
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
                    new_activator_evals.push(B::F::one());
                    new_inner_evals.push(*val);
                }
            });
        new_activator_evals.resize(1 << new_nv, B::F::zero());
        new_inner_evals.resize(1 << new_nv, B::F::zero());
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

        let rematerialize_check_prover_input = RematerializeCheckProverInput {
            input_tracked_col: col.clone(),
            output_tracked_col: new_col.clone(),
        };
        RematerializeCheck::<B>::prove(tracker, rematerialize_check_prover_input)?;
        Ok(new_col)
    }

    pub fn defrag_tracked_col_oracle(
        verifier: &mut ArgVerifier<B>,
        tracked_col_oracle: &TrackedColOracle<B>,
    ) -> SnarkResult<TrackedColOracle<B>> {
        if tracked_col_oracle.activator_tracked_oracle().is_none() {
            return Ok(tracked_col_oracle.clone());
        }

        let new_col_inner_tr = verifier.track_next_mv_com()?;
        let new_col_activator_tr = verifier.track_next_mv_com()?;

        let new_tracked_col_oracle = TrackedColOracle::new(
            new_col_inner_tr.clone(),
            Some(new_col_activator_tr),
            tracked_col_oracle.field_ref().clone(),
        );

        let rematerialize_check_verifier_input = RematerializeCheckVerifierInput {
            input_tracked_col_oracle: tracked_col_oracle.clone(),
            output_tracked_col_oracle: new_tracked_col_oracle.clone(),
        };
        RematerializeCheck::<B>::verify(verifier, rematerialize_check_verifier_input)?;
        Ok(new_tracked_col_oracle)
    }
}
