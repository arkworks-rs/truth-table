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
pub struct GroupingSetPIOPProverInput {
    pub grouping_set: datafusion::logical_expr::expr::GroupingSet,
}

#[derive(Clone, Debug)]
pub struct GroupingSetPIOPVerifierInput {
    pub grouping_set: datafusion::logical_expr::expr::GroupingSet,
}

pub struct GroupingSetExprPIOP;

impl_expr_piop_deep_clone!(GroupingSetPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for GroupingSetExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = GroupingSetPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = GroupingSetPIOPVerifierInput;

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
