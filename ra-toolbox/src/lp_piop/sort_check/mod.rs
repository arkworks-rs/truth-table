mod perm;
mod sort;
use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
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
pub struct SortTrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The expression to sort on
    pub expr: TrackedCol<F, MvPCS, UvPCS>,
    /// The expression shifted by one position (wrap-around)
    pub shifted_expr: TrackedCol<F, MvPCS, UvPCS>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for SortTrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            expr: self.expr.deep_clone(new_prover.clone()),
            shifted_expr: self.shifted_expr.deep_clone(new_prover),
            asc: self.asc,
            nulls_first: self.nulls_first,
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct SortTrackedColOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The expression to sort on
    pub expr: TrackedColOracle<F, MvPCS, UvPCS>,
    /// The expression shifted by one position (wrap-around)
    pub shifted_expr: TrackedColOracle<F, MvPCS, UvPCS>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

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
    pub sort: Sort,
    pub sort_exprs: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub sroted_sort_exprs: Vec<SortTrackedCol<F, MvPCS, UvPCS>>,
    pub tie_indicator_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub table: TrackedTable<F, MvPCS, UvPCS>,
    pub lex_sorted_table: TrackedTable<F, MvPCS, UvPCS>,
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
    pub sort: Sort,
    pub sort_exprs: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub sroted_sort_exprs: Vec<SortTrackedColOracle<F, MvPCS, UvPCS>>,
    pub tie_indicator_cols: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub table: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub lex_sorted_table: TrackedTableOracle<F, MvPCS, UvPCS>,
}
impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for SortPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            sort: self.sort.clone(),
            sort_exprs: self
                .sort_exprs
                .iter()
                .map(|expr| expr.deep_clone(new_prover.clone()))
                .collect(),
            sroted_sort_exprs: self
                .sroted_sort_exprs
                .iter()
                .map(|expr| expr.deep_clone(new_prover.clone()))
                .collect(),
            tie_indicator_cols: self
                .tie_indicator_cols
                .iter()
                .map(|col| col.deep_clone(new_prover.clone()))
                .collect(),
            table: self.table.deep_clone(new_prover.clone()),
            lex_sorted_table: self.lex_sorted_table.deep_clone(new_prover),
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
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
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
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
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
