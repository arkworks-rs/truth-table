pub mod comparison;
pub mod or;
pub mod utils;
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError::ProverError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{
        Prover,
        errors::{HonestProverError::FalseClaim, ProverError::HonestProverError},
    },
    verifier::Verifier,
};
use datafusion::logical_expr::Operator;
use derivative::Derivative;

use crate::expr_piop::binary_expr::comparison::{ComparisonExprPIOP, is_comparison_op};
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
        use crate::expr_piop::binary_expr::utils::activators_match;

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
        if is_comparison_op(&input.op) {
            ComparisonExprPIOP::prove(prover, input)
        } else {
            match input.op {
                Operator::And => Ok(()),
                Operator::Or => or::OrBinaryExprPIOP::prove(prover, input),
                _ => unimplemented!("Proving for this operator is not implemented yet"),
            }
        }
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        if is_comparison_op(&input.op) {
            ComparisonExprPIOP::verify(verifier, input)
        } else {
            match input.op {
                Operator::And => Ok(()),
                Operator::Or => or::OrBinaryExprPIOP::verify(verifier, input),
                _ => unimplemented!("Verifying for this operator is not implemented yet"),
            }
        }
    }
}
