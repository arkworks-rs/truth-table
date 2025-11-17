use crate::expr_piop::impl_expr_piop_deep_clone;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::ArgProver,
    verifier::Verifier,
};

#[derive(Clone, Debug)]
pub struct BetweenPIOPProverInput {
    pub between: datafusion::logical_expr::expr::Between,
}

#[derive(Clone, Debug)]
pub struct BetweenPIOPVerifierInput {
    pub between: datafusion::logical_expr::expr::Between,
}

pub struct BetweenExprPIOP;

impl_expr_piop_deep_clone!(BetweenPIOPProverInput);

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for BetweenExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = BetweenPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = BetweenPIOPVerifierInput;

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
