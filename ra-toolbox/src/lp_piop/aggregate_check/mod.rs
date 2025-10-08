use crate::utils::fold_polys;
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
use col_toolbox::supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput};
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
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let num_gpd_cols = input.input_grouping_table.num_data_tracked_cols();
        // Generate one random field element for each column being grouped by
        // This is used to fold these columns to a single random linearly
        // combined column
        let gpd_cols_fld_challs: Vec<F> = (0..num_gpd_cols)
            .map(|_| {
                prover
                    .get_and_append_challenge(b"Grouping columns folding challeng")
                    .unwrap()
            })
            .collect();

        // Fold the grouping columns of the input and output tables

        let input_folded_col = input.input_grouping_table.fold_all_data_columns(&gpd_cols_fld_challs);
        let output_folded_col = input.output_grouping_table.fold_all_data_columns(&gpd_cols_fld_challs);

        // Invoke the support check PIOP to check
        let supp_check_input = SuppCheckProverInput {
            col: input_folded_col.clone(),
            supp: output_folded_col.clone(),
        };

        let supp_check_output = SuppCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, supp_check_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let num_gpd_cols = input.input_grouping_table_oracle.num_data_tracked_col_oracles();
        // Generate one random field element for each column being grouped by
        // This is used to fold these columns to a single random linearly
        // combined column
        let gpd_cols_fld_challs: Vec<F> = (0..num_gpd_cols)
            .map(|_| {
                verifier
                    .get_and_append_challenge(b"Grouping columns folding challeng")
                    .unwrap()
            })
            .collect();

        // Fold the grouping columns of the input and output tables

        let input_folded_col_oracle = input
            .input_grouping_table_oracle
            .fold_all_data_columns(&gpd_cols_fld_challs);
        let output_folded_col_oracle = input
            .output_grouping_table_oracle
            .fold_all_data_columns(&gpd_cols_fld_challs);

        // Invoke the support check PIOP to check
        let supp_check_input = SuppCheckVerifierInput {
            col: input_folded_col_oracle.clone(),
            supp: output_folded_col_oracle.clone(),
        };

        let supp_check_output =
            SuppCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, supp_check_input)?;
        Ok(())
    }
}

#[cfg(test)]
mod test;
