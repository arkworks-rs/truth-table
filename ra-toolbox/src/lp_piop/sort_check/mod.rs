#[cfg(test)]
mod test;

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
            expr: self.expr.deep_clone(new_prover),
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
    pub input_sort_exprs: Vec<SortTrackedCol<F, MvPCS, UvPCS>>,
    pub output_sort_exprs: Vec<SortTrackedCol<F, MvPCS, UvPCS>>,
    pub input_table: TrackedTable<F, MvPCS, UvPCS>,
    pub output_table: TrackedTable<F, MvPCS, UvPCS>,
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
    pub input_sort_exprs: Vec<SortTrackedColOracle<F, MvPCS, UvPCS>>,
    pub output_sort_exprs: Vec<SortTrackedColOracle<F, MvPCS, UvPCS>>,
    pub input_table: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub output_table: TrackedTableOracle<F, MvPCS, UvPCS>,
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
            input_sort_exprs: self
                .input_sort_exprs
                .iter()
                .map(|expr| expr.deep_clone(new_prover.clone()))
                .collect(),
            output_sort_exprs: self
                .output_sort_exprs
                .iter()
                .map(|expr| expr.deep_clone(new_prover.clone()))
                .collect(),
            input_table: self.input_table.deep_clone(new_prover.clone()),
            output_table: self.output_table.deep_clone(new_prover),
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

    fn prove_inner(
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        Ok(())
    }

    fn verify_inner(
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Ok(())
    }
}
