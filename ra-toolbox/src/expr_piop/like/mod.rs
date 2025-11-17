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
pub struct LikePIOPProverInput {
    pub like: datafusion::logical_expr::expr::Like,
}

#[derive(Clone, Debug)]
pub struct LikePIOPVerifierInput {
    pub like: datafusion::logical_expr::expr::Like,
}

pub struct LikeExprPIOP;

impl_expr_piop_deep_clone!(LikePIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for LikeExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = LikePIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = LikePIOPVerifierInput;

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
