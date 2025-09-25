use crate::expr_piop::impl_expr_piop_deep_clone;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};

#[derive(Clone, Debug)]
pub struct SimilarToPIOPProverInput {
    pub like: datafusion::logical_expr::expr::Like,
}

#[derive(Clone, Debug)]
pub struct SimilarToPIOPVerifierInput {
    pub like: datafusion::logical_expr::expr::Like,
}

pub struct SimilarToExprPIOP;

impl_expr_piop_deep_clone!(SimilarToPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for SimilarToExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = SimilarToPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = SimilarToPIOPVerifierInput;

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
