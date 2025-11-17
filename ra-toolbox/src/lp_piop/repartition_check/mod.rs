use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::Verifier,
};
use datafusion::logical_expr::Repartition;

#[derive(Debug, Clone)]
pub struct RepartitionPIOPProverInput {
    pub repartition: Repartition,
}

#[derive(Debug, Clone)]
pub struct RepartitionPIOPVerifierInput {
    pub repartition: Repartition,
}

pub struct RepartitionPIOP;

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for RepartitionPIOP
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = RepartitionPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = RepartitionPIOPVerifierInput;

    fn prove_inner(
        _prover: &mut ArgProver<F, MvPCS, UvPCS>,
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

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for RepartitionPIOPProverInput
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, _new_prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod test;
