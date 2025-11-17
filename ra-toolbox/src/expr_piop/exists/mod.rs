use crate::expr_piop::impl_expr_piop_deep_clone;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::ArgProver,
    verifier::Verifier,
};

#[derive(Clone, Debug)]
pub struct ExistsPIOPProverInput {
    pub exists: datafusion::logical_expr::expr::Exists,
}

#[derive(Clone, Debug)]
pub struct ExistsPIOPVerifierInput {
    pub exists: datafusion::logical_expr::expr::Exists,
}

pub struct ExistsExprPIOP;

impl_expr_piop_deep_clone!(ExistsPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for ExistsExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = ExistsPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = ExistsPIOPVerifierInput;

    fn prove_inner(
        _prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let _ = input;
        Ok(())
    }

    fn verify_inner(
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let _ = input;
        Ok(())
    }
}
