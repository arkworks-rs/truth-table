use crate::expr_piop::binary_expr::comparison::{
    InnerComparisonPIOPProverInput, InnerComparisonPIOPVerifierInput,
};

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::ArgProver,
    verifier::ArgVerifier,
};
use col_toolbox::{
    binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};
use std::marker::PhantomData;

pub struct EqBinaryExprPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(PhantomData<F>, PhantomData<MvPCS>, PhantomData<UvPCS>);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for EqBinaryExprPIOP<F, MvPCS, UvPCS>
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
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO: Implement honest prover check for equality PIOP.
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let binary_check_prover_input = BinaryCheckProverInput {
            predicate: input
                .bin_expr_piop_prover_input
                .output_col
                .activated_data_tracked_poly()
                .clone(),
        };
        BinaryCheckPIOP::prove(prover, binary_check_prover_input)?;

        let activator = input
            .bin_expr_piop_prover_input
            .left_col
            .activator_tracked_poly();
        let left_data = input
            .bin_expr_piop_prover_input
            .left_col
            .data_tracked_poly();
        let right_data = input
            .bin_expr_piop_prover_input
            .right_col
            .data_tracked_poly();
        let output_data = input
            .bin_expr_piop_prover_input
            .output_col
            .data_tracked_poly();
        let diff = &left_data - &right_data;

        let zero_poly = match activator.as_ref() {
            Some(activator_tracked_poly) => &diff * &(&output_data * activator_tracked_poly),
            None => &diff * &output_data,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        let output_minus_one = &output_data - F::one();
        let one_minus_output = &output_minus_one * F::one().neg();
        let gated_activator = match activator.clone() {
            Some(act) => Some(&act * &one_minus_output),
            None => Some(one_minus_output.clone()),
        };

        let no_zero_col = TrackedCol::new(diff, gated_activator, None);
        NoZerosCheck::<F, MvPCS, UvPCS>::prove(
            prover,
            NoZerosCheckProverInput { col: no_zero_col },
        )?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let binary_check_verifier_input = BinaryCheckVerifierInput {
            predicate_oracle: input
                .bin_expr_piop_verifier_input
                .output_col_oracle
                .activated_data_tracked_oracle()
                .clone(),
        };
        BinaryCheckPIOP::verify(verifier, binary_check_verifier_input)?;

        let activator = input
            .bin_expr_piop_verifier_input
            .left_col_oracle
            .activator_tracked_oracle();
        let left_data = input
            .bin_expr_piop_verifier_input
            .left_col_oracle
            .data_tracked_oracle();
        let right_data = input
            .bin_expr_piop_verifier_input
            .right_col_oracle
            .data_tracked_oracle();
        let output_data = input
            .bin_expr_piop_verifier_input
            .output_col_oracle
            .data_tracked_oracle();
        let diff = &left_data - &right_data;

        let zero_poly = match activator.as_ref() {
            Some(activator_tracked_poly) => &diff * &(&output_data * activator_tracked_poly),
            None => &diff * &output_data,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        let output_minus_one = &output_data - F::one();
        let one_minus_output = &output_minus_one * F::one().neg();
        let gated_activator = match activator.clone() {
            Some(act) => Some(&act * &one_minus_output),
            None => Some(one_minus_output.clone()),
        };

        let no_zero_col = TrackedColOracle::new(diff, gated_activator, None);
        NoZerosCheck::<F, MvPCS, UvPCS>::verify(
            verifier,
            NoZerosCheckVerifierInput {
                tracked_col_oracle: no_zero_col,
            },
        )?;
        Ok(())
    }
}
