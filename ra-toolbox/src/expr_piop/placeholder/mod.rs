use crate::expr_piop::impl_expr_piop_deep_clone;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::ArgProver,
    verifier::ArgVerifier,
};

#[derive(Clone, Debug)]
pub struct PlaceholderPIOPProverInput {
    pub placeholder: datafusion::logical_expr::expr::Placeholder,
}

#[derive(Clone, Debug)]
pub struct PlaceholderPIOPVerifierInput {
    pub placeholder: datafusion::logical_expr::expr::Placeholder,
}

pub struct PlaceholderExprPIOP;

impl_expr_piop_deep_clone!(PlaceholderPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for PlaceholderExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = PlaceholderPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = PlaceholderPIOPVerifierInput;

    fn prove_inner(
        _prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let _ = input;
        Ok(())
    }

    fn verify_inner(
        _verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let _ = input;
        Ok(())
    }
}
