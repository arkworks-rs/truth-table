use crate::expr_piop::binary_expr::comparison::{
    InnerComparisonPIOPProverInput, InnerComparisonPIOPVerifierInput,
};

use super::{BinaryExprPIOPProverInput, BinaryExprPIOPVerifierInput};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};
use std::marker::PhantomData;

pub struct NotEqBinaryExprPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(PhantomData<F>, PhantomData<MvPCS>, PhantomData<UvPCS>);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for NotEqBinaryExprPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = InnerComparisonPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = InnerComparisonPIOPVerifierInput<F, MvPCS, UvPCS>;

    fn prove_inner(
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        todo!("NotEqBinaryExprPIOP::prove_inner")
    }

    fn verify_inner(
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        todo!("NotEqBinaryExprPIOP::verify_inner")
    }
}
