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
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use col_toolbox::{
    multi_col_supp_check::{
        MultiColSuppCheckPIOP, MultiColSuppCheckProverInput, MultiColSuppCheckVerifierInput,
    },
    supp_check::{HintedSuppCheckPIOP, HintedSuppCheckProverInput, HintedSuppCheckVerifierInput},
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
    pub contig_lex_sorted_output_grouping_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub shifted_contig_lex_sorted_output_grouping_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub tie_indicator_tracked_table: Option<TrackedTable<F, MvPCS, UvPCS>>,
    pub grouping_multiplicity_tracked_poly: TrackedPoly<F, MvPCS, UvPCS>,
}
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct AggregatePIOPProverOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_folded_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub output_folded_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
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
    pub contig_lex_sorted_output_grouping_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub shifted_contig_lex_sorted_output_grouping_tracked_table_oracle:
        TrackedTableOracle<F, MvPCS, UvPCS>,
    pub tie_indicator_tracked_table_oracle: Option<TrackedTableOracle<F, MvPCS, UvPCS>>,
    pub grouping_multiplicty_tracked_oracle: TrackedOracle<F, MvPCS, UvPCS>,
}
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct AggregatePIOPVerifierOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_folded_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub output_folded_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
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
    type ProverOutput = AggregatePIOPProverOutput<F, MvPCS, UvPCS>;
    type VerifierOutput = AggregatePIOPVerifierOutput<F, MvPCS, UvPCS>;
    type VerifierInput = AggregatePIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let multi_col_supp_check_prover_input = MultiColSuppCheckProverInput {
            orig_tracked_table: input.input_grouping_table.clone(),
            supp_tracked_table: input.output_grouping_table.clone(),
            contig_lex_sorted_supp_tracked_table: input
                .contig_lex_sorted_output_grouping_tracked_table
                .clone(),
            shifted_contig_lex_sorted_supp_tracked_table: input
                .shifted_contig_lex_sorted_output_grouping_tracked_table
                .clone(),
            tie_indicator_tracked_table: input.tie_indicator_tracked_table.clone(),
            multiplicity: input.grouping_multiplicity_tracked_poly.clone(),
        };
        let multi_col_supp_check_prover_output = MultiColSuppCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            multi_col_supp_check_prover_input,
        )?;
        Ok(AggregatePIOPProverOutput {
            input_folded_tracked_col: multi_col_supp_check_prover_output.orig_folded_tracked_col,
            output_folded_tracked_col: multi_col_supp_check_prover_output.supp_folded_tracked_col,
        })
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let multi_col_supp_check_verifier_input = MultiColSuppCheckVerifierInput {
            orig_tracked_table_oracle: input.input_grouping_table_oracle.clone(),
            supp_tracked_table_oracle: input.output_grouping_table_oracle.clone(),
            contig_lex_sorted_supp_tracked_table_oracle: input
                .contig_lex_sorted_output_grouping_tracked_table_oracle
                .clone(),
            shifted_contig_lex_sorted_supp_tracked_table_oracle: input
                .shifted_contig_lex_sorted_output_grouping_tracked_table_oracle
                .clone(),
            tie_indicator_tracked_table_oracle: input.tie_indicator_tracked_table_oracle.clone(),
            multiplicity: input.grouping_multiplicty_tracked_oracle.clone(),
        };
        let multi_col_supp_check_prover_output = MultiColSuppCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            multi_col_supp_check_verifier_input,
        )?;
        Ok(AggregatePIOPVerifierOutput {
            input_folded_tracked_col_oracle: multi_col_supp_check_prover_output
                .orig_folded_tracked_col_oracle,
            output_folded_tracked_col_oracle: multi_col_supp_check_prover_output
                .supp_folded_tracked_col_oracle,
        })
    }
}
