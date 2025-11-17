use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::Verifier,
};
use datafusion::logical_expr::Distinct;

#[derive(Debug, Clone)]
pub struct DistinctPIOPProverInput {
    pub distinct: Distinct,
}

#[derive(Debug, Clone)]
pub struct DistinctPIOPVerifierInput {
    pub distinct: Distinct,
}

pub struct DistinctPIOP;

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for DistinctPIOP
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = DistinctPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = DistinctPIOPVerifierInput;

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

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for DistinctPIOPProverInput
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
