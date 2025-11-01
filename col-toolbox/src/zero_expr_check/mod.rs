use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};

#[cfg(feature = "honest-prover")]
use ark_piop::prover::errors::{HonestProverError, ProverError};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ZeroExprCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub selector_col: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for ZeroExprCheckProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            tracked_col: self.tracked_col.deep_clone(prover.clone()),
            selector_col: self.selector_col.deep_clone(prover),
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ZeroExprCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub selector_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

pub struct ZeroExprCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for ZeroExprCheckPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = ZeroExprCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = ZeroExprCheckVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let ZeroExprCheckProverInput {
            tracked_col,
            selector_col,
        } = input;

        BinaryCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            BinaryCheckProverInput {
                predicate: selector_col.activated_data_tracked_poly(),
            },
        )?;

        let activator = tracked_col.activator_tracked_poly();
        let tracked_data = tracked_col.data_tracked_poly();
        let selector_data = selector_col.data_tracked_poly();

        let zero_poly = match activator.as_ref() {
            Some(act) => &(&tracked_data * &selector_data) * act,
            None => &tracked_data * &selector_data,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        let one_minus_selector = &(&selector_data * F::one().neg()) + F::one();
        let gated_activator = match activator {
            Some(act) => Some(&act * &one_minus_selector),
            None => Some(one_minus_selector.clone()),
        };

        let non_zero_col = TrackedCol::new(tracked_data, gated_activator, tracked_col.field_ref());

        NoZerosCheck::<F, MvPCS, UvPCS>::prove(
            prover,
            NoZerosCheckProverInput { col: non_zero_col },
        )?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let ZeroExprCheckVerifierInput {
            tracked_col_oracle,
            selector_col_oracle,
        } = input;

        BinaryCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            BinaryCheckVerifierInput {
                predicate_oracle: selector_col_oracle.activated_data_tracked_oracle(),
            },
        )?;

        let activator = tracked_col_oracle.activator_tracked_oracle();
        let tracked_data = tracked_col_oracle.data_tracked_oracle();
        let selector_data = selector_col_oracle.data_tracked_oracle();

        let zero_oracle = match activator.as_ref() {
            Some(act) => &(&tracked_data * &selector_data) * act,
            None => &tracked_data * &selector_data,
        };
        verifier.add_zerocheck_claim(zero_oracle.id());

        let one_minus_selector = &(&selector_data * F::one().neg()) + F::one();
        let gated_activator = match activator {
            Some(act) => Some(&act * &one_minus_selector),
            None => Some(one_minus_selector.clone()),
        };

        let non_zero_col = TrackedColOracle::new(
            tracked_data,
            gated_activator,
            tracked_col_oracle.field_ref(),
        );

        NoZerosCheck::<F, MvPCS, UvPCS>::verify(
            verifier,
            NoZerosCheckVerifierInput {
                tracked_col_oracle: non_zero_col,
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "fill in zero expression check tests"]
    fn zero_expr_check_placeholder() {
        assert!(true);
    }
}
