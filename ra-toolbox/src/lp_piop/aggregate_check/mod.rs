use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use datafusion::logical_expr::Aggregate;
use derivative::Derivative;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct AggregatePIOPProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub aggregate: Aggregate,
    pub input_grouping_table: TrackedTable<F, MvPCS, UvPCS>,
    pub output_grouping_table: TrackedTable<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for AggregatePIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, _new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        self.clone()
    }
}
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct AggregatePIOPVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub aggregate: Aggregate,
    pub input_grouping_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub output_grouping_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
}

pub struct AggregatePIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    _field: std::marker::PhantomData<F>,
    _mvpcs: std::marker::PhantomData<MvPCS>,
    _uvpcs: std::marker::PhantomData<UvPCS>,
}

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for AggregatePIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = AggregatePIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = AggregatePIOPVerifierInput<F, MvPCS, UvPCS>;

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

#[cfg(test)]
mod test;
