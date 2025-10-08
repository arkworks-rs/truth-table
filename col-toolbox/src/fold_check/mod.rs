//! A PIOP for checking if a column is the result of folding other columns
//!
//! More precisely, this PIOP checks if the activated portion of a column is the
//! result of a random linear combination of the activated portion of other
//! columns, with respect to a set of random challenges.

#[cfg(test)]
mod test;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use derivative::Derivative;
use std::marker::PhantomData;
pub struct FoldCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct FoldCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    // The input columns to be folded
    pub in_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    // The column that is the result of folding the input columns
    pub folded_col: TrackedCol<F, MvPCS, UvPCS>,
    // The challenges used for folding
    pub challs: Vec<F>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for FoldCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
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

pub struct FoldCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    // The input column comitments to be folded
    pub in_cms: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    // The commitment of the column that is the result of folding the input columns
    pub folded_cm: TrackedColOracle<F, MvPCS, UvPCS>,
    // The challenges used for folding
    pub challs: Vec<F>,
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> PIOP<F, MvPCS, UvPCS>
    for FoldCheckPIOP<F, MvPCS, UvPCS>
where
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = FoldCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = FoldCheckVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
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
            acc_poly = &acc_poly - &(&poly * *chall);
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
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let mut zero_comm = input.folded_cm.activated_data_tracked_oracle();
        for (poly_comm, chall) in input.in_cms.iter().zip(input.challs.iter()) {
            zero_comm = &zero_comm - &(&poly_comm.activated_data_tracked_oracle() * (*chall));
        }
        verifier.add_zerocheck_claim(zero_comm.id());
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let mut tartracked_poly = input.folded_col.activated_data_tracked_poly().clone();
        for (tracked_poly, chall) in input.in_cols.iter().zip(input.challs.iter()) {
            tartracked_poly -= &(&tracked_poly.activated_data_tracked_poly() * *chall);
        }
        prover.add_mv_zerocheck_claim(tartracked_poly.id())?;
        Ok(())
    }
}
