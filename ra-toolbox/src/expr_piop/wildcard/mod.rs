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
pub struct WildcardPIOPProverInput {
    pub qualifier: Option<datafusion::common::TableReference>,
    pub options: Box<datafusion::logical_expr::expr::WildcardOptions>,
}

#[derive(Clone, Debug)]
pub struct WildcardPIOPVerifierInput {
    pub qualifier: Option<datafusion::common::TableReference>,
    pub options: Box<datafusion::logical_expr::expr::WildcardOptions>,
}

pub struct WildcardExprPIOP;

impl_expr_piop_deep_clone!(WildcardPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for WildcardExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = WildcardPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = WildcardPIOPVerifierInput;

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
