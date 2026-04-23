//! A PIOP for checking if a column is the result of folding other columns
//!
//! More precisely, this PIOP checks if the activated portion of a column is the
//! result of a random linear combination of the activated portion of other
//! columns, with respect to a set of random challenges.

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use derivative::Derivative;
use std::marker::PhantomData;
pub struct FoldCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct FoldCheckProverInput<B: SnarkBackend> {
    // The input columns to be folded
    pub in_cols: Vec<TrackedCol<B>>,
    // The column that is the result of folding the input columns
    pub folded_col: TrackedCol<B>,
    // The challenges used for folding
    pub challs: Vec<B::F>,
}

impl<B: SnarkBackend> DeepClone<B> for FoldCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            in_cols: self
                .in_cols
                .iter()
                .map(|col| col.deep_clone(prover.clone()))
                .collect(),
            folded_col: self.folded_col.deep_clone(prover),
            challs: self.challs.clone(),
        }
    }
}

pub struct FoldCheckVerifierInput<B: SnarkBackend> {
    // The input column commitments to be folded
    pub in_cms: Vec<TrackedColOracle<B>>,
    // The commitment of the column that is the result of folding the input columns
    pub folded_cm: TrackedColOracle<B>,
    // The challenges used for folding
    pub challs: Vec<B::F>,
}

impl<B: SnarkBackend> PIOP<B> for FoldCheckPIOP<B> {
    type ProverInput = FoldCheckProverInput<B>;
    type ProverOutput = ();
    type VerifierInput = FoldCheckVerifierInput<B>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use ark_ff::Zero;
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let mut acc_poly = input.folded_col.activated_data_tracked_poly().clone();
        for (poly, chall) in input
            .in_cols
            .iter()
            .map(|col| col.activated_data_tracked_poly())
            .zip(input.challs.iter())
        {
            acc_poly = &acc_poly - &(poly.clone() * *chall);
        }
        for &eval in acc_poly.evaluations().iter() {
            if !eval.is_zero() {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let mut zero_comm = input.folded_cm.activated_data_tracked_oracle();
        for (poly_comm, chall) in input.in_cms.iter().zip(input.challs.iter()) {
            zero_comm =
                &zero_comm - &(poly_comm.activated_data_tracked_oracle().clone() * (*chall));
        }
        verifier.add_mv_zerocheck_claim(zero_comm.id());
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let mut tartracked_poly = input.folded_col.activated_data_tracked_poly().clone();
        for (tracked_poly, chall) in input.in_cols.iter().zip(input.challs.iter()) {
            tartracked_poly -= &(tracked_poly.activated_data_tracked_poly().clone() * *chall);
        }
        prover.add_mv_zerocheck_claim(tartracked_poly.id())?;
        Ok(())
    }
}
