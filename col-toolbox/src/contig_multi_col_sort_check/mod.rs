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

use crate::local_single_col_sort_check::{self, LocalSingleColSortCheckProverInput};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSortCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub tie_indicator_tracked_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub shift_tracked_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub ascending: bool,
    pub strict: bool,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for MultiColSortCheckProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            tracked_cols: self
                .tracked_cols
                .iter()
                .map(|col| col.deep_clone(prover.clone()))
                .collect(),
            tie_indicator_tracked_cols: self
                .tie_indicator_tracked_cols
                .iter()
                .map(|col| col.deep_clone(prover.clone()))
                .collect(),
            shift_tracked_cols: self
                .shift_tracked_cols
                .iter()
                .map(|col| col.deep_clone(prover.clone()))
                .collect(),
            ascending: self.ascending,
            strict: self.strict,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSortCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col_oracles: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub tie_indicator_tracked_col_oracles: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub shift_tracked_col_oracles: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub ascending: bool,
    pub strict: bool,
}

pub struct MultiColSortCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for MultiColSortCheckPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = MultiColSortCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = MultiColSortCheckVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        _input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let num_cols = _input.tracked_cols.len();

        let current_tie_indicator_col: Option<TrackedCol<F, MvPCS, UvPCS>> = None;

        for i in 0..num_cols {
            let local_single_col_sort_check_prover_input = LocalSingleColSortCheckProverInput {
                tracked_col: _input.tracked_cols[i].clone(),
                tie_indicator_col: _input.tie_indicator_tracked_cols[i].clone(),
                shift_col: _input.shift_tracked_cols[i].clone(),
                ascending: _input.ascending,
                strict: _input.strict,
            };
            let local_single_col_sort_check_prover_output =
                local_single_col_sort_check::LocalSingleColSortCheckPIOP::prove(
                    prover,
                    local_single_col_sort_check_prover_input,
                )?;
        }

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
