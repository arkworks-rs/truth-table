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
pub struct OuterReferenceColumnPIOPProverInput {
    pub data_type: datafusion::arrow::datatypes::DataType,
    pub column: datafusion::common::Column,
}

#[derive(Clone, Debug)]
pub struct OuterReferenceColumnPIOPVerifierInput {
    pub data_type: datafusion::arrow::datatypes::DataType,
    pub column: datafusion::common::Column,
}

pub struct OuterReferenceColumnExprPIOP;

impl_expr_piop_deep_clone!(OuterReferenceColumnPIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for OuterReferenceColumnExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = OuterReferenceColumnPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = OuterReferenceColumnPIOPVerifierInput;

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
