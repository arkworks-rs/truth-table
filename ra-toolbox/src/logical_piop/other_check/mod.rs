use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use datafusion::logical_expr::LogicalPlan;

#[derive(Debug, Clone)]
pub struct OtherPIOPProverInput {
    pub logical_plan: LogicalPlan,
}

#[derive(Debug, Clone)]
pub struct OtherPIOPVerifierInput {
    pub logical_plan: LogicalPlan,
}

pub struct OtherPIOP;

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for OtherPIOP
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = OtherPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = OtherPIOPVerifierInput;

    fn prove_inner(
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        Ok(())
    }

    fn verify_inner(
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for OtherPIOPProverInput
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, _new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod test;
