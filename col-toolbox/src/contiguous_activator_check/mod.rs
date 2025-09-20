//! A PIOP to check if two columns are a permutation of each other.
// More precisely, this PIOP checks if the activated elements of one column
// are a permutation of the activated elements of another column.
// #[cfg(test)]
// mod test;

use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError::ProverError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{
        Prover,
        errors::{HonestProverError::FalseClaim, ProverError::HonestProverError},
    },
    verifier::Verifier,
};
use derivative::Derivative;
use std::marker::PhantomData;
// Convinces the verifier that
pub struct ContiguousActivatorCheck<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ContiguousActivatorCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col: ArithCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for ContiguousActivatorCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            col: self.col.deep_clone(prover.clone()),
        }
    }
}

pub struct ContiguousActivatorCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub com: ColCom<F, MvPCS, UvPCS>,
}
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for ContiguousActivatorCheck<F, MvPCS, UvPCS>
{
    type ProverInput = ContiguousActivatorCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = ContiguousActivatorCheckVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        if !input.col.effective_iter().into_iter().is_sorted() {
            return Err(ProverError(HonestProverError(FalseClaim)));
        }
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        todo!()
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        todo!()
    }
}
