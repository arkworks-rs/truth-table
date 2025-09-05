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
    prover::{Prover, structs::polynomial::TrackedPoly},
    timed,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use std::marker::PhantomData;

pub struct BinaryCheckPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

pub struct BinaryCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub activator: TrackedPoly<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for BinaryCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            activator: self.activator.deep_clone(prover),
        }
    }
}

pub struct BinaryCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub activator_comm: TrackedOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for BinaryCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = BinaryCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = BinaryCheckVerifierInput<F, MvPCS, UvPCS>;

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        for elem in input.activator.evaluations().iter() {
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
    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<()> {
        // set up the tracker and add a zerocheck claim
        let one_minus_sel = &(&input.activator * F::one().neg()) + F::one();
        let check_poly = &input.activator * &one_minus_sel;
        prover.add_mv_zerocheck_claim(check_poly.id())?;
        Ok(())
    }

    #[timed]
    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<()> {
        let one_minus_sel = &(&input.activator_comm * (F::one().neg())) + (F::one());
        let check_poly = &(input.activator_comm) * &one_minus_sel;
        verifier.add_zerocheck_claim(check_poly.id);
        Ok(())
    }
}
