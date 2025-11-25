use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use datafusion::logical_expr::Analyze;

#[derive(Debug, Clone)]
pub struct AnalyzePIOPProverInput {
    pub analyze: Analyze,
}

#[derive(Debug, Clone)]
pub struct AnalyzePIOPVerifierInput {
    pub analyze: Analyze,
}

pub struct AnalyzePIOP;

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for AnalyzePIOP
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    type ProverInput = AnalyzePIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = AnalyzePIOPVerifierInput;

    fn prove_inner(
        _prover: &mut ArgProver<F, MvPCS, UvPCS>,
        _input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        Ok(())
    }

    fn verify_inner(
        _verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        _input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for AnalyzePIOPProverInput
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn deep_clone(&self, _new_prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod test;
