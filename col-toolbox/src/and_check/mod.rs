//! A PIOP for checking that a new activator is the AND of the input activators

#[cfg(test)]
mod test;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, errors::ProverError::HonestProverError, structs::polynomial::TrackedPoly},
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use std::marker::PhantomData;
use derivative::Derivative;
pub struct AndCheckPIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct AndCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub in_activator_polys: Vec<TrackedPoly<F, MvPCS, UvPCS>>,
    pub res_activator_poly: TrackedPoly<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for AndCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        let mut in_activator_polys_cloned = Vec::new();
        for activator_oply in &self.in_activator_polys {
            in_activator_polys_cloned.push(activator_oply.deep_clone(prover.clone()));
        }
        Self {
            in_activator_polys: in_activator_polys_cloned,
            res_activator_poly: self.res_activator_poly.deep_clone(prover),
        }
    }
}

pub struct AndCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub in_activator_orcls: Vec<TrackedOracle<F, MvPCS, UvPCS>>,
    pub res_activator_orcl: TrackedOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for AndCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = AndCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = AndCheckVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        let mut prod_poly = input.in_activator_polys[0].clone();
        for in_poly in &input.in_activator_polys {
            prod_poly *= in_poly;
        }
        let check_poly = &prod_poly - &input.res_activator_poly;
        if (check_poly.evaluations().iter().all(|&elem| elem.is_zero())) {
            return Ok(());
        } else {
            return Err(ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim,
                ),
            ));
        }
    }
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<()> {
        // Rust Ownership and borrow rules
        let mut prod_poly = input.in_activator_polys[0].clone();
        for in_poly in &input.in_activator_polys {
            prod_poly *= in_poly;
        }
        let check_poly = &input.res_activator_poly - &prod_poly;
        prover.add_mv_zerocheck_claim(check_poly.id())?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<()> {
        let mut prod_orcl = input.in_activator_orcls[0].clone();
        for in_orcl in &input.in_activator_orcls {
            prod_orcl = &prod_orcl * in_orcl;
        }
        let check_orcl = &input.res_activator_orcl - &prod_orcl;
        verifier.add_zerocheck_claim(check_orcl.id);
        Ok(())
    }
}
