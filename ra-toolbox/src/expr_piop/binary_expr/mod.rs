use crate::expr_piop::impl_expr_piop_deep_clone;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};

#[derive(Clone, Debug)]
pub struct BinaryExprPIOPProverInput {
    pub binary: datafusion::logical_expr::expr::BinaryExpr,
}

#[derive(Clone, Debug)]
pub struct BinaryExprPIOPVerifierInput {
    pub binary: datafusion::logical_expr::expr::BinaryExpr,
}

pub struct BinaryExprExprPIOP;

impl_expr_piop_deep_clone!(BinaryExprPIOPProverInput);
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for BinaryExprExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = BinaryExprPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = BinaryExprPIOPVerifierInput;

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
