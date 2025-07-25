//! A PIOP for checking if a column is the result of folding other columns
//!
//! More precisely, this PIOP checks if the activated portion of a column is the
//! result of a random linear combination of the activated portion of other
//! columns, with respect to a set of random challenges.

#[cfg(test)]
mod test;

use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    timed,
    verifier::Verifier,
};
use std::marker::PhantomData;
pub struct FoldCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

pub struct FoldCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    // The input columns to be folded
    pub in_cols: Vec<ArithCol<F, MvPCS, UvPCS>>,
    // The column that is the result of folding the input columns
    pub folded_col: ArithCol<F, MvPCS, UvPCS>,
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
    // The input column commitments to be folded
    pub in_cms: Vec<ColCom<F, MvPCS, UvPCS>>,
    // The commitment of the column that is the result of folding the input columns
    pub folded_cm: ColCom<F, MvPCS, UvPCS>,
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

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        for &eval in input
            .in_cols
            .iter()
            .map(|col| col.activated_data_poly())
            .zip(input.challs.iter())
            .fold(
                input.folded_col.activated_data_poly().clone(),
                |acc, (poly, chall)| acc.sub_poly(&poly.mul_scalar(*chall)),
            )
            .evaluations()
            .iter()
        {
            if !eval.is_zero() {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        Ok(())
    }

    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let mut zero_comm = input.folded_cm.effective_comm().clone();
        for (poly_comm, chall) in input.in_cms.iter().zip(input.challs.iter()) {
            zero_comm = &zero_comm - &(&poly_comm.effective_comm() * (*chall));
        }
        verifier.add_zerocheck_claim(zero_comm.id);
        Ok(())
    }

    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let mut target_tracked_poly = input.folded_col.activated_data_poly().clone();
        for (tracked_poly, chall) in input.in_cols.iter().zip(input.challs.iter()) {
            target_tracked_poly = target_tracked_poly
                .sub_poly(&tracked_poly.activated_data_poly().mul_scalar(*chall));
        }
        prover.add_mv_zerocheck_claim(target_tracked_poly.get_id())?;
        Ok(())
    }
}
