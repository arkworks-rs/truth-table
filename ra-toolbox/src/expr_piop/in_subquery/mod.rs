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
pub struct InSubqueryPIOPProverInput {
    pub in_subquery: datafusion::logical_expr::expr::InSubquery,
}

#[derive(Clone, Debug)]
pub struct InSubqueryPIOPVerifierInput {
    pub in_subquery: datafusion::logical_expr::expr::InSubquery,
}

pub struct InSubqueryExprPIOP;

impl_expr_piop_deep_clone!(InSubqueryPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for InSubqueryExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = InSubqueryPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = InSubqueryPIOPVerifierInput;

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
