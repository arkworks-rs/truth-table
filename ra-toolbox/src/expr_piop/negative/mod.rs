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
pub struct NegativePIOPProverInput {
    pub expr: Box<datafusion::logical_expr::Expr>,
}

#[derive(Clone, Debug)]
pub struct NegativePIOPVerifierInput {
    pub expr: Box<datafusion::logical_expr::Expr>,
}

pub struct NegativeExprPIOP;

impl_expr_piop_deep_clone!(NegativePIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for NegativeExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    type ProverInput = NegativePIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = NegativePIOPVerifierInput;

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
