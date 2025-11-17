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
pub struct InListPIOPProverInput {
    pub in_list: datafusion::logical_expr::expr::InList,
}

#[derive(Clone, Debug)]
pub struct InListPIOPVerifierInput {
    pub in_list: datafusion::logical_expr::expr::InList,
}

pub struct InListExprPIOP;

impl_expr_piop_deep_clone!(InListPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for InListExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = InListPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = InListPIOPVerifierInput;

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
