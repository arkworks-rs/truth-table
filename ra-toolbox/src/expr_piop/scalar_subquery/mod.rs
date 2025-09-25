use crate::expr_piop::impl_expr_piop_deep_clone;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};
use datafusion::logical_expr::Subquery;

#[derive(Clone, Debug)]
pub struct ScalarSubqueryPIOPProverInput {
    pub subquery: Subquery,
}

#[derive(Clone, Debug)]
pub struct ScalarSubqueryPIOPVerifierInput {
    pub subquery: Subquery,
}

pub struct ScalarSubqueryExprPIOP;

impl_expr_piop_deep_clone!(ScalarSubqueryPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for ScalarSubqueryExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = ScalarSubqueryPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = ScalarSubqueryPIOPVerifierInput;

    fn prove_inner(
        _prover: &mut Prover<F, MvPCS, UvPCS>,
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
