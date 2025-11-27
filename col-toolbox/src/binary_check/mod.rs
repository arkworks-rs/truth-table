//! A PIOP for checking that a column only contains binary values (0 or 1).
//!
//! More precisely, this PIOP checks if the activated elements of a column are
//! either 0 or 1.

#[cfg(test)]
mod test;
use ark_ff::One;
use ark_ff::Zero;
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;
use std::ops::Neg;
pub struct BinaryCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BinaryCheckProverInput<B: SnarkBackend> {
    pub predicate: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for BinaryCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            predicate: self.predicate.deep_clone(prover),
        }
    }
}

pub struct BinaryCheckVerifierInput<B: SnarkBackend> {
    pub predicate_oracle: TrackedOracle<B>,
}

impl<B: SnarkBackend> PIOP<B> for BinaryCheckPIOP<B> {
    type ProverInput = BinaryCheckProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = BinaryCheckVerifierInput<B>;

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
    fn prove_inner(prover: &mut ArgProver<B>, input: Self::ProverInput) -> SnarkResult<()> {
        // set up the tracker and add a zerocheck claim
        let predicate = input.predicate;
        let one_minus_sel = predicate
            .mul_scalar_poly(B::F::one().neg())
            .add_scalar_poly(B::F::one());
        let check_poly = &predicate * &one_minus_sel;
        prover.add_mv_zerocheck_claim(check_poly.id())?;
        Ok(())
    }

    fn verify_inner(verifier: &mut ArgVerifier<B>, input: Self::VerifierInput) -> SnarkResult<()> {
        let predicate = input.predicate_oracle;
        let one_minus_sel = predicate
            .mul_scalar_oracle(B::F::one().neg())
            .add_scalar_oracle(B::F::one());
        let check_poly = &predicate * &one_minus_sel;
        verifier.add_zerocheck_claim(check_poly.id());
        Ok(())
    }
}
