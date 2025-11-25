//! A PIOP for checking that a column only contains binary values (0 or 1).
//!
//! More precisely, this PIOP checks if the activated elements of a column are
//! either 0 or 1.

#[cfg(test)]
mod test;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct BinaryCheckPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BinaryCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub predicate: TrackedPoly<F, MvPCS, UvPCS>,
}

impl<F: PrimeField,     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,>
    DeepClone<F, MvPCS, UvPCS> for BinaryCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        Self {
            predicate: self.predicate.deep_clone(prover),
        }
    }
}

pub struct BinaryCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub predicate_oracle: TrackedOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField,     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,>
    PIOP<F, MvPCS, UvPCS> for BinaryCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = BinaryCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = BinaryCheckVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        for elem in input.predicate.evaluations().iter() {
            if !elem.is_zero() && !elem.is_one() {
                return Err(ark_piop::errors::SnarkError::ProverError(
                    ark_piop::prover::errors::ProverError::HonestProverError(
                        ark_piop::prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
            }
        }

        Ok(())
    }
    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<()> {
        // set up the tracker and add a zerocheck claim
        let one_minus_sel = &(&input.predicate * F::one().neg()) + F::one();
        let check_poly = &input.predicate * &one_minus_sel;
        prover.add_mv_zerocheck_claim(check_poly.id())?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<()> {
        let one_minus_sel = &(&input.predicate_oracle * F::one().neg()) + F::one();
        let check_poly = &(input.predicate_oracle) * &one_minus_sel;
        verifier.add_zerocheck_claim(check_poly.id());
        Ok(())
    }
}
