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
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};

use col_toolbox::bezout_based_multi_col_supp_check::{
    BezoutMultiColSuppCheckPIOP, BezoutMultiColSuppCheckProverInput,
    BezoutMultiColSuppCheckVerifierInput,
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
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub aggregate: Aggregate,
    pub input_grouping_table: TrackedTable<F, MvPCS, UvPCS>,
    pub output_grouping_table: TrackedTable<F, MvPCS, UvPCS>,
}
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct AggregatePIOPProverOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub input_folded_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub output_folded_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub multiplicity_poly: TrackedPoly<F, MvPCS, UvPCS>,
}
impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for AggregatePIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn deep_clone(&self, _new_prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
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
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub aggregate: Aggregate,
    pub input_grouping_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub output_grouping_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
}
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct AggregatePIOPVerifierOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub input_folded_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub output_folded_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub multiplicity_oracle: TrackedOracle<F, MvPCS, UvPCS>,
}
pub struct AggregatePIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    _field: std::marker::PhantomData<F>,
    _mvpcs: std::marker::PhantomData<MvPCS>,
    _uvpcs: std::marker::PhantomData<UvPCS>,
}

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for AggregatePIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    type ProverInput = AggregatePIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = AggregatePIOPProverOutput<F, MvPCS, UvPCS>;
    type VerifierOutput = AggregatePIOPVerifierOutput<F, MvPCS, UvPCS>;
    type VerifierInput = AggregatePIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let multi_col_supp_check_prover_input = BezoutMultiColSuppCheckProverInput {
            orig_tracked_table: input.input_grouping_table.clone(),
            supp_tracked_table: input.output_grouping_table.clone(),
        };
        let multi_col_supp_check_prover_output =
            BezoutMultiColSuppCheckPIOP::<F, MvPCS, UvPCS>::prove(
                prover,
                multi_col_supp_check_prover_input,
            )?;
        Ok(AggregatePIOPProverOutput {
            input_folded_tracked_col: multi_col_supp_check_prover_output.orig_folded_tracked_col,
            output_folded_tracked_col: multi_col_supp_check_prover_output.supp_folded_tracked_col,
            multiplicity_poly: multi_col_supp_check_prover_output.multiplicity,
        })
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let multi_col_supp_check_verifier_input = BezoutMultiColSuppCheckVerifierInput {
            orig_tracked_table_oracle: input.input_grouping_table_oracle.clone(),
            supp_tracked_table_oracle: input.output_grouping_table_oracle.clone(),
        };
        let multi_col_supp_check_prover_output =
            BezoutMultiColSuppCheckPIOP::<F, MvPCS, UvPCS>::verify(
                verifier,
                multi_col_supp_check_verifier_input,
            )?;
        Ok(AggregatePIOPVerifierOutput {
            input_folded_tracked_col_oracle: multi_col_supp_check_prover_output
                .orig_folded_tracked_col_oracle,
            output_folded_tracked_col_oracle: multi_col_supp_check_prover_output
                .supp_folded_tracked_col_oracle,
            multiplicity_oracle: multi_col_supp_check_prover_output.multiplicity,
        })
    }
}
