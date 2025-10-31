use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{arithmetic::mat_poly::{lde::LDE, mle::MLE}, errors::SnarkResult, pcs::PCS, piop::{DeepClone, PIOP}, prover::Prover, verifier::Verifier};
use derivative::Derivative;
use std::marker::PhantomData;

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ZeroExprCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub selector_col: Option<TrackedCol<F, MvPCS, UvPCS>>,
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
            selector_col: self
                .selector_col
                .as_ref()
                .map(|col| col.deep_clone(prover)),
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
    pub selector_col_oracle: Option<TrackedColOracle<F, MvPCS, UvPCS>>,
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
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        _input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let _ = prover;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let _ = verifier;
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
