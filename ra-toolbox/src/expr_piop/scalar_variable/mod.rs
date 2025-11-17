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
pub struct ScalarVariablePIOPProverInput {
    pub data_type: datafusion::arrow::datatypes::DataType,
    pub path: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ScalarVariablePIOPVerifierInput {
    pub data_type: datafusion::arrow::datatypes::DataType,
    pub path: Vec<String>,
}

pub struct ScalarVariableExprPIOP;

impl_expr_piop_deep_clone!(ScalarVariablePIOPProverInput);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for ScalarVariableExprPIOP
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = ScalarVariablePIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = ScalarVariablePIOPVerifierInput;

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
