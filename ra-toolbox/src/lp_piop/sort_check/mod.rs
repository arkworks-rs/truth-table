mod perm;
mod sort;
use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use datafusion::logical_expr::Sort;
use derivative::Derivative;

use crate::lp_piop::sort_check::{
    perm::{perm_prove, perm_verify},
    sort::{lex_sort_prove, lex_sort_verify},
};

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct SortPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The sort logical plan
    pub sort_lp: Sort,
    /// The sort expressions packed in a tracked table
    pub sort_exprs_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    /// The lexicographically sorted sort expressions packed in a tracked table
    pub lex_sorted_sort_exprs_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    /// The shifted lexicographically sorted sort expressions packed in a
    /// tracked table
    pub shifted_lex_sorted_sort_exprs_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    /// The tie indicators packed in a tracked table
    pub tie_indicators_tracked_table: Option<TrackedTable<F, MvPCS, UvPCS>>,
    /// The original table packed in a tracked table
    pub tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    /// The lexicographically sorted table packed in a tracked table
    pub lex_sorted_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    /// Indicates for each sort column whether the sort is ascending
    pub ascending_vec: Vec<bool>,
    /// Indicates for each sort column whether the sort is strict
    pub null_first_vec: Vec<bool>,
}
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct SortPIOPVerifierInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The sort logical plan
    pub sort_lp: Sort,
    /// The sort expressions packed in a tracked table oracle
    pub sort_exprs_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    /// The lexicographically sorted sort expressions packed in a tracked table
    /// oracle
    pub lex_sorted_sort_exprs_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    /// The shifted lexicographically sorted sort expressions packed in a
    /// tracked table oracle
    pub shifted_lex_sorted_sort_exprs_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    /// The tie indicators packed in a tracked table oracle
    pub tie_indicators_tracked_table_oracle: Option<TrackedTableOracle<F, MvPCS, UvPCS>>,
    /// The original table packed in a tracked table oracle
    pub tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    /// The lexicographically sorted table packed in a tracked table oracle
    pub lex_sorted_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    /// Indicates for each sort column whether the sort is ascending
    pub ascending_vec: Vec<bool>,
    /// Indicates for each sort column whether the sort is strict
    pub null_first_vec: Vec<bool>,
}
impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for SortPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, new_prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        Self {
            sort_lp: self.sort_lp.clone(),
            sort_exprs_tracked_table: self.sort_exprs_tracked_table.deep_clone(new_prover.clone()),
            lex_sorted_sort_exprs_tracked_table: self
                .lex_sorted_sort_exprs_tracked_table
                .deep_clone(new_prover.clone()),
            shifted_lex_sorted_sort_exprs_tracked_table: self
                .shifted_lex_sorted_sort_exprs_tracked_table
                .deep_clone(new_prover.clone()),
            tie_indicators_tracked_table: self
                .tie_indicators_tracked_table
                .as_ref()
                .map(|table| table.deep_clone(new_prover.clone())),
            tracked_table: self.tracked_table.deep_clone(new_prover.clone()),
            lex_sorted_tracked_table: self.lex_sorted_tracked_table.deep_clone(new_prover),
            ascending_vec: self.ascending_vec.clone(),
            null_first_vec: self.null_first_vec.clone(),
        }
    }
}

pub struct SortPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    _field: std::marker::PhantomData<F>,
    _mvpcs: std::marker::PhantomData<MvPCS>,
    _uvpcs: std::marker::PhantomData<UvPCS>,
}

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for SortPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = SortPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = SortPIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // First, Prove that the table coupled with the original sort
        // expressions is a permutation of the lexicographically sorted
        // table coupled with the sorted expressions
        perm_prove(prover, &input)?;

        // Second, Prove that the sorted exprs are actually sorted lexicographically
        lex_sort_prove(prover, &input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // First, Verify that the table coupled with the original sort
        // expressions is a permutation of the lexicographically sorted
        // table coupled with the sorted expressions
        perm_verify(verifier, &input)?;
        // Second, Verify that the sorted exprs are actually sorted lexicographically
        lex_sort_verify(verifier, &input)?;
        Ok(())
    }
}
