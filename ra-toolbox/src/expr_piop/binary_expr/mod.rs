pub mod utils;

use crate::expr_piop::binary_expr::utils::invert_or_one_in_place;
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{PrimeField, batch_inversion};
#[cfg(feature = "honest-prover")]
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError::ProverError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{
        self, Prover,
        errors::{HonestProverError::FalseClaim, ProverError::HonestProverError},
    },
    verifier::Verifier,
};
use col_toolbox::{
    binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};
use datafusion::logical_expr::Operator;
use derivative::Derivative;
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct BinaryExprPIOPProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub op: Operator,
    pub left_col: TrackedCol<F, MvPCS, UvPCS>,
    pub right_col: TrackedCol<F, MvPCS, UvPCS>,
    pub output_col: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for BinaryExprPIOPProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            op: self.op,
            left_col: self.left_col.deep_clone(prover.clone()),
            right_col: self.right_col.deep_clone(prover.clone()),
            output_col: self.output_col.deep_clone(prover),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BinaryExprPIOPVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub op: Operator,
    pub left_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub right_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub output_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

pub struct BinaryExprPIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    std::marker::PhantomData<F>,
    std::marker::PhantomData<MvPCS>,
    std::marker::PhantomData<UvPCS>,
);

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for BinaryExprPIOP<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = BinaryExprPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = BinaryExprPIOPVerifierInput<F, MvPCS, UvPCS>;
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        if input.left_col.data_tracked_poly().log_size()
            != input.right_col.data_tracked_poly().log_size()
            || input.left_col.data_tracked_poly().log_size()
                != input.output_col.data_tracked_poly().log_size()
        {
            return Err(ProverError(HonestProverError(FalseClaim)));
        }

        let left_act = input.left_col.activator_tracked_poly();
        let right_act = input.right_col.activator_tracked_poly();
        let output_act = input.output_col.activator_tracked_poly();
        if !activators_match::<F, MvPCS, UvPCS>(left_act.clone(), right_act.clone())
            || !activators_match::<F, MvPCS, UvPCS>(left_act.clone(), output_act.clone())
            || !activators_match::<F, MvPCS, UvPCS>(right_act.clone(), output_act.clone())
        {
            return Err(ProverError(HonestProverError(FalseClaim)));
        }
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        match input.op {
            Operator::And => {},
            Operator::Or => {
                let binary_check_prover_input = BinaryCheckProverInput {
                    predicate: input.output_col.activated_data_tracked_poly().clone(),
                };
                BinaryCheckPIOP::prove(prover, binary_check_prover_input)?;

                let col_left_right_sum =
                    &input.left_col.data_tracked_poly() + &input.right_col.data_tracked_poly();
                let mut p_evals = col_left_right_sum.evaluations().to_vec();
                invert_or_one_in_place(&mut p_evals);
                let p_poly = MLE::from_evaluations_vec(col_left_right_sum.log_size(), p_evals);
                let p_tracked = prover.track_and_commit_mat_mv_poly(&p_poly)?;
                let zero_poly = match (
                    input.left_col.activator_tracked_poly(),
                    input.output_col.activator_tracked_poly(),
                ) {
                    (Some(in_activator_tracked_poly), Some(out_activator_tracked_poly)) => {
                        &(&(&in_activator_tracked_poly * &p_tracked)
                            * &(&input.left_col.data_tracked_poly()
                                + &input.right_col.data_tracked_poly()))
                            - &(&input.output_col.data_tracked_poly() * &out_activator_tracked_poly)
                    },
                    (Some(in_activator_tracked_poly), None) => {
                        &(&(&in_activator_tracked_poly * &p_tracked)
                            * &(&input.left_col.data_tracked_poly()
                                + &input.right_col.data_tracked_poly()))
                            - &input.output_col.data_tracked_poly()
                    },
                    (None, Some(out_activator_tracked_poly)) => {
                        &(&p_tracked
                            * &(&input.left_col.data_tracked_poly()
                                + &input.right_col.data_tracked_poly()))
                            - &(&input.output_col.data_tracked_poly() * &out_activator_tracked_poly)
                    },
                    (None, None) => {
                        &(&p_tracked
                            * &(&input.left_col.data_tracked_poly()
                                + &input.right_col.data_tracked_poly()))
                            - &input.output_col.data_tracked_poly()
                    },
                };
                prover.add_mv_zerocheck_claim(zero_poly.id())?;
            },
            Operator::Eq => {
                let binary_check_prover_input = BinaryCheckProverInput {
                    predicate: input.output_col.activated_data_tracked_poly().clone(),
                };
                BinaryCheckPIOP::prove(prover, binary_check_prover_input)?;

                let activator = input.left_col.activator_tracked_poly();
                let left_data = input.left_col.data_tracked_poly();
                let right_data = input.right_col.data_tracked_poly();
                let output_data = input.output_col.data_tracked_poly();
                let diff = &left_data - &right_data;

                let zero_poly = match activator.as_ref() {
                    Some(activator_tracked_poly) => {
                        &diff * &(&output_data * activator_tracked_poly)
                    },
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
            },
            Operator::NotEq => todo!(),
            Operator::Lt => todo!(),
            Operator::LtEq => todo!(),
            Operator::Gt => todo!(),
            Operator::GtEq => todo!(),
            _ => panic!("Unsupported binary operator in BinaryExprPIOP"),
        }
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        match input.op {
            Operator::And => {},
            Operator::Or => {
                let binary_check_verifier_input = BinaryCheckVerifierInput {
                    predicate_oracle: input
                        .output_col_oracle
                        .activated_data_tracked_oracle()
                        .clone(),
                };
                BinaryCheckPIOP::verify(verifier, binary_check_verifier_input)?;

                let col_left_right_sum = &input.left_col_oracle.data_tracked_oracle()
                    + &input.right_col_oracle.data_tracked_oracle();
                let p_id = verifier.peek_next_id();
                let p_tracked = verifier.track_mv_com_by_id(p_id)?;
                let zero_poly = match (
                    input.left_col_oracle.activator_tracked_oracle(),
                    input.output_col_oracle.activator_tracked_oracle(),
                ) {
                    (Some(in_activator_tracked_poly), Some(out_activator_tracked_poly)) => {
                        &(&(&in_activator_tracked_poly * &p_tracked)
                            * &(&input.left_col_oracle.data_tracked_oracle()
                                + &input.right_col_oracle.data_tracked_oracle()))
                            - &(&input.output_col_oracle.data_tracked_oracle()
                                * &out_activator_tracked_poly)
                    },
                    (Some(in_activator_tracked_poly), None) => {
                        &(&(&in_activator_tracked_poly * &p_tracked)
                            * &(&input.left_col_oracle.data_tracked_oracle()
                                + &input.right_col_oracle.data_tracked_oracle()))
                            - &input.output_col_oracle.data_tracked_oracle()
                    },
                    (None, Some(out_activator_tracked_poly)) => {
                        &(&p_tracked
                            * &(&input.left_col_oracle.data_tracked_oracle()
                                + &input.right_col_oracle.data_tracked_oracle()))
                            - &(&input.output_col_oracle.data_tracked_oracle()
                                * &out_activator_tracked_poly)
                    },
                    (None, None) => {
                        &(&p_tracked
                            * &(&input.left_col_oracle.data_tracked_oracle()
                                + &input.right_col_oracle.data_tracked_oracle()))
                            - &input.output_col_oracle.data_tracked_oracle()
                    },
                };
                verifier.add_zerocheck_claim(zero_poly.id());
            },
            Operator::Eq => {
                let binary_check_verifier_input = BinaryCheckVerifierInput {
                    predicate_oracle: input
                        .output_col_oracle
                        .activated_data_tracked_oracle()
                        .clone(),
                };
                BinaryCheckPIOP::verify(verifier, binary_check_verifier_input)?;

                let activator = input.left_col_oracle.activator_tracked_oracle();
                let left_data = input.left_col_oracle.data_tracked_oracle();
                let right_data = input.right_col_oracle.data_tracked_oracle();
                let output_data = input.output_col_oracle.data_tracked_oracle();
                let diff = &left_data - &right_data;

                let zero_poly = match activator.as_ref() {
                    Some(activator_tracked_poly) => {
                        &diff * &(&output_data * activator_tracked_poly)
                    },
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
            },
            Operator::NotEq => todo!(),
            Operator::Lt => todo!(),
            Operator::LtEq => todo!(),
            Operator::Gt => todo!(),
            Operator::GtEq => todo!(),
            _ => panic!("Unsupported binary operator in BinaryExprPIOP"),
        }
        Ok(())
    }
}

#[cfg(feature = "honest-prover")]
fn activators_match<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    lhs: Option<TrackedPoly<F, MvPCS, UvPCS>>,
    rhs: Option<TrackedPoly<F, MvPCS, UvPCS>>,
) -> bool {
    match (lhs, rhs) {
        (None, None) => true,
        (Some(poly), None) | (None, Some(poly)) => activator_is_all_ones(&poly),
        (Some(lhs_poly), Some(rhs_poly)) => {
            lhs_poly.log_size() == rhs_poly.log_size()
                && lhs_poly.evaluations() == rhs_poly.evaluations()
        },
    }
}
#[cfg(feature = "honest-prover")]
fn activator_is_all_ones<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    poly: &TrackedPoly<F, MvPCS, UvPCS>,
) -> bool {
    poly.evaluations().into_iter().all(|val| val == F::one())
}
