use crate::expr_piop::binary_expr::comparison::{
    InnerComparisonPIOPProverInput, InnerComparisonPIOPVerifierInput,
};

use super::{BinaryExprPIOPProverInput, BinaryExprPIOPVerifierInput};
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};
use col_toolbox::{
    binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput},
    sign_check::{SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput},
};
use std::marker::PhantomData;

pub struct LtEqBinaryExprPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(PhantomData<F>, PhantomData<MvPCS>, PhantomData<UvPCS>);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for LtEqBinaryExprPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = InnerComparisonPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = InnerComparisonPIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let non_neg_sign_check_prover_input = SignCheckProverInput {
            col: input.selected_left_minus_right_col,
            sign: col_toolbox::sign_check::Sign::NonePositive,
        };
        SignCheckPIOP::prove(prover, non_neg_sign_check_prover_input)?;

        let neg_sign_check_prover_input = SignCheckProverInput {
            col: input.non_selected_left_minus_right_col,
            sign: col_toolbox::sign_check::Sign::Positive,
        };
        SignCheckPIOP::prove(prover, neg_sign_check_prover_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let non_neg_sign_check_verifier_input = SignCheckVerifierInput {
            tracked_col_oracle: input.selected_left_minus_right_oracle,
            sign: col_toolbox::sign_check::Sign::NonePositive,
        };
        SignCheckPIOP::verify(verifier, non_neg_sign_check_verifier_input)?;

        let neg_sign_check_verifier_input = SignCheckVerifierInput {
            tracked_col_oracle: input.non_selected_left_minus_right_oracle,
            sign: col_toolbox::sign_check::Sign::Positive,
        };
        SignCheckPIOP::verify(verifier, neg_sign_check_verifier_input)?;

        Ok(())
    }
}
