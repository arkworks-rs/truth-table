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
use derivative::Derivative;
use std::marker::PhantomData;

use crate::sign_check::{Sign, SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LocalSingleColSortCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub tie_indicator_col: TrackedCol<F, MvPCS, UvPCS>,
    pub shift_col: TrackedCol<F, MvPCS, UvPCS>,
    pub ascending: bool,
    pub strict: bool,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS>
    for LocalSingleColSortCheckProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            tracked_col: self.tracked_col.deep_clone(prover.clone()),
            tie_indicator_col: self.tie_indicator_col.deep_clone(prover.clone()),
            shift_col: self.shift_col.deep_clone(prover),
            ascending: self.ascending,
            strict: self.strict,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LocalSingleColSortCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub tie_indicator_col_oracle: Option<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub shift_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub ascending: bool,
    pub strict: bool,
}

pub struct LocalSingleColSortCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for LocalSingleColSortCheckPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = LocalSingleColSortCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = LocalSingleColSortCheckVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let diff_col = TrackedCol::new(
            &input.shift_col.data_tracked_poly() - &input.tracked_col.data_tracked_poly(),
            Some(input.tie_indicator_col.data_tracked_poly()),
            input.tracked_col.field_ref(),
        );
        let sign = match (input.ascending, input.strict) {
            (true, true) => Sign::Positive,
            (true, false) => Sign::NoneNegative,
            (false, true) => Sign::Negative,
            (false, false) => Sign::NonePositive,
        };

        let sign_check_prover_input = SignCheckProverInput {
            col: diff_col,
            sign,
        };
        SignCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, sign_check_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let LocalSingleColSortCheckVerifierInput {
            tracked_col_oracle,
            tie_indicator_col_oracle,
            shift_col_oracle,
            ascending,
            strict,
        } = input;

        let tie_indicator_col_oracle = tie_indicator_col_oracle.expect(
            "tie indicator column oracle must be provided for local single column sort check",
        );

        let mut diff_data_oracle = shift_col_oracle.data_tracked_oracle();
        diff_data_oracle -= &tracked_col_oracle.data_tracked_oracle();

        let diff_col_oracle = TrackedColOracle::new(
            diff_data_oracle,
            Some(tie_indicator_col_oracle.data_tracked_oracle()),
            tracked_col_oracle.field_ref(),
        );

        let sign = match (ascending, strict) {
            (true, true) => Sign::Positive,
            (true, false) => Sign::NoneNegative,
            (false, true) => Sign::Negative,
            (false, false) => Sign::NonePositive,
        };

        let sign_check_input = SignCheckVerifierInput {
            tracked_col_oracle: diff_col_oracle,
            sign,
        };

        SignCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, sign_check_input)
    }
}
