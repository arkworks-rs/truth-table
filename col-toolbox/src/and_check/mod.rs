//! A PIOP for checking that a new activator is the AND of the input activators

#[cfg(test)]
mod test;
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;
pub struct AndCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct AndCheckProverInput<B: SnarkBackend> {
    pub in_activator_tracked_polys: Vec<TrackedPoly<B>>,
    pub res_activator_tracked_poly: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for AndCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        let mut in_activator_tracked_polys_cloned = Vec::new();
        for activator_oply in &self.in_activator_tracked_polys {
            in_activator_tracked_polys_cloned.push(activator_oply.deep_clone(prover.clone()));
        }
        Self {
            in_activator_tracked_polys: in_activator_tracked_polys_cloned,
            res_activator_tracked_poly: self.res_activator_tracked_poly.deep_clone(prover),
        }
    }
}

pub struct AndCheckVerifierInput<B: SnarkBackend> {
    pub in_activator_orcls: Vec<TrackedOracle<B>>,
    pub res_activator_orcl: TrackedOracle<B>,
}

impl<B: SnarkBackend> PIOP<B> for AndCheckPIOP<B> {
    type ProverInput = AndCheckProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = AndCheckVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        use ark_std::Zero;
        let mut prod_poly = input.in_activator_tracked_polys[0].clone();
        for in_poly in &input.in_activator_tracked_polys {
            prod_poly *= in_poly;
        }
        let check_poly = &prod_poly - &input.res_activator_tracked_poly;
        if check_poly.evaluations().iter().all(|&elem| elem.is_zero()) {
            return Ok(());
        }
        Err(ark_piop::errors::SnarkError::ProverError(
            ark_piop::prover::errors::ProverError::HonestProverError(
                ark_piop::prover::errors::HonestProverError::FalseClaim,
            ),
        ))
    }
    fn prove_inner(prover: &mut ArgProver<B>, input: Self::ProverInput) -> SnarkResult<()> {
        // Rust Ownership and borrow rules
        let mut prod_poly = input.in_activator_tracked_polys[0].clone();
        for in_poly in &input.in_activator_tracked_polys {
            prod_poly *= in_poly;
        }
        let check_poly = &input.res_activator_tracked_poly - &prod_poly;
        prover.add_mv_zerocheck_claim(check_poly.id())?;
        Ok(())
    }

    fn verify_inner(verifier: &mut ArgVerifier<B>, input: Self::VerifierInput) -> SnarkResult<()> {
        let mut prod_orcl = input.in_activator_orcls[0].clone();
        for in_orcl in &input.in_activator_orcls {
            prod_orcl = &prod_orcl * in_orcl;
        }
        let check_orcl = &input.res_activator_orcl - &prod_orcl;
        verifier.add_zerocheck_claim(check_orcl.id());
        Ok(())
    }
}
