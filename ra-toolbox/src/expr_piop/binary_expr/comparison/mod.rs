mod eq;
mod gt;
mod gt_eq;
mod lt;
mod lt_eq;
mod not_eq;

use crate::expr_piop::binary_expr::comparison::{
    eq::EqBinaryExprPIOP, gt::GtBinaryExprPIOP, gt_eq::GtEqBinaryExprPIOP, lt::LtBinaryExprPIOP,
    lt_eq::LtEqBinaryExprPIOP, not_eq::NotEqBinaryExprPIOP,
};

use super::{BinaryExprPIOPProverInput, BinaryExprPIOPVerifierInput};
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use col_toolbox::binary_check::{
    BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput,
};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct ComparisonExprPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(PhantomData<F>, PhantomData<MvPCS>, PhantomData<UvPCS>);

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct InnerComparisonPIOPProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub bin_expr_piop_prover_input: BinaryExprPIOPProverInput<F, MvPCS, UvPCS>,
    pub selected_left_minus_right_col: TrackedCol<F, MvPCS, UvPCS>,
    pub non_selected_left_minus_right_col: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for InnerComparisonPIOPProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            bin_expr_piop_prover_input: self.bin_expr_piop_prover_input.deep_clone(prover.clone()),
            selected_left_minus_right_col: self
                .selected_left_minus_right_col
                .deep_clone(prover.clone()),
            non_selected_left_minus_right_col: self
                .non_selected_left_minus_right_col
                .deep_clone(prover),
        }
    }
}

pub struct InnerComparisonPIOPVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub bin_expr_piop_verifier_input: BinaryExprPIOPVerifierInput<F, MvPCS, UvPCS>,
    pub selected_left_minus_right_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub non_selected_left_minus_right_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for ComparisonExprPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = BinaryExprPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = BinaryExprPIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let binary_check_prover_input = BinaryCheckProverInput {
            predicate: input.output_col.activated_data_tracked_poly().clone(),
        };
        BinaryCheckPIOP::prove(prover, binary_check_prover_input)?;

        let left_data = input.left_col.data_tracked_poly();
        let right_data = input.right_col.data_tracked_poly();
        let output_data = input.output_col.data_tracked_poly();
        let diff = &left_data - &right_data;
        let selector = match input.left_col.activator_tracked_poly() {
            Some(act) => Some(&act * &output_data),
            None => Some(output_data.clone()),
        };

        let selected_col =
            TrackedCol::new(diff.clone(), selector.clone(), input.left_col.field_ref());

        let output_minus_one = &output_data - F::one();
        let one_minus_output = &output_minus_one * F::one().neg();
        let selector = match input.left_col.activator_tracked_poly() {
            Some(act) => Some(&act * &one_minus_output),
            None => Some(one_minus_output.clone()),
        };

        let non_selected_col = TrackedCol::new(diff, selector, input.left_col.field_ref());
        let inner_comparison_prover_input = InnerComparisonPIOPProverInput {
            bin_expr_piop_prover_input: input.clone(),
            selected_left_minus_right_col: selected_col,
            non_selected_left_minus_right_col: non_selected_col,
        };

        match input.op {
            datafusion::logical_expr::Operator::Eq => {
                EqBinaryExprPIOP::prove(prover, inner_comparison_prover_input)
            },
            datafusion::logical_expr::Operator::NotEq => {
                NotEqBinaryExprPIOP::prove(prover, inner_comparison_prover_input)
            },
            datafusion::logical_expr::Operator::Lt => {
                LtBinaryExprPIOP::prove(prover, inner_comparison_prover_input)
            },
            datafusion::logical_expr::Operator::LtEq => {
                LtEqBinaryExprPIOP::prove(prover, inner_comparison_prover_input)
            },
            datafusion::logical_expr::Operator::Gt => {
                GtBinaryExprPIOP::prove(prover, inner_comparison_prover_input)
            },
            datafusion::logical_expr::Operator::GtEq => {
                GtEqBinaryExprPIOP::prove(prover, inner_comparison_prover_input)
            },
            _ => unreachable!("is_comparison_op should ensure this is a comparison operator"),
        }
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let binary_check_verifier_input = BinaryCheckVerifierInput {
            predicate_oracle: input
                .output_col_oracle
                .activated_data_tracked_oracle()
                .clone(),
        };
        BinaryCheckPIOP::verify(verifier, binary_check_verifier_input)?;

        let left_data = input.left_col_oracle.data_tracked_oracle();
        let right_data = input.right_col_oracle.data_tracked_oracle();
        let output_data = input.output_col_oracle.data_tracked_oracle();
        let diff = &left_data - &right_data;
        let selector = match input.left_col_oracle.activator_tracked_oracle() {
            Some(act) => Some(&act * &output_data),
            None => Some(output_data.clone()),
        };

        let selected_col = TrackedColOracle::new(
            diff.clone(),
            selector.clone(),
            input.left_col_oracle.field_ref(),
        );

        let output_minus_one = &output_data - F::one();
        let one_minus_output = &output_minus_one * F::one().neg();
        let selector = match input.left_col_oracle.activator_tracked_oracle() {
            Some(act) => Some(&act * &one_minus_output),
            None => Some(one_minus_output.clone()),
        };
        let non_selected_col =
            TrackedColOracle::new(diff, selector, input.left_col_oracle.field_ref());
        let inner_comparison_verifier_input = InnerComparisonPIOPVerifierInput {
            bin_expr_piop_verifier_input: input.clone(),
            selected_left_minus_right_oracle: selected_col,
            non_selected_left_minus_right_oracle: non_selected_col,
        };

        match input.op {
            datafusion::logical_expr::Operator::Eq => {
                EqBinaryExprPIOP::verify(verifier, inner_comparison_verifier_input)
            },
            datafusion::logical_expr::Operator::NotEq => {
                NotEqBinaryExprPIOP::verify(verifier, inner_comparison_verifier_input)
            },
            datafusion::logical_expr::Operator::Lt => {
                LtBinaryExprPIOP::verify(verifier, inner_comparison_verifier_input)
            },
            datafusion::logical_expr::Operator::LtEq => {
                LtEqBinaryExprPIOP::verify(verifier, inner_comparison_verifier_input)
            },
            datafusion::logical_expr::Operator::Gt => {
                GtBinaryExprPIOP::verify(verifier, inner_comparison_verifier_input)
            },
            datafusion::logical_expr::Operator::GtEq => {
                GtEqBinaryExprPIOP::verify(verifier, inner_comparison_verifier_input)
            },
            _ => unreachable!("is_comparison_op should ensure this is a comparison operator"),
        }
    }
}

pub fn is_comparison_op(op: &datafusion::logical_expr::Operator) -> bool {
    use datafusion::logical_expr::Operator::*;
    matches!(op, Eq | NotEq | Lt | LtEq | Gt | GtEq)
}
