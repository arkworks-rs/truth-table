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
pub struct CastPIOPProverInput {
    pub cast: datafusion::logical_expr::expr::Cast,
}

#[derive(Clone, Debug)]
pub struct CastPIOPVerifierInput {
    pub cast: datafusion::logical_expr::expr::Cast,
}

pub struct CastExprPIOP;

impl_expr_piop_deep_clone!(CastPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for CastExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    type ProverInput = CastPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = CastPIOPVerifierInput;

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
