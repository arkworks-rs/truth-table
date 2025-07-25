//! A PIOP for checking if a group-by sql query was done correctly
//!
//! More precisely, this PIOP, given the input and ouput tables of a aggregation
//! operation and further a statistical function (like sum, avg, etc) checks if
//! the output was aggregated correctly based on the grouping columns and the
//! statistics are correct

///////////////// Modules /////////////////
mod grouping_check;
mod stat_check;
pub mod structs;
#[cfg(test)]
mod test;
mod utils;
////////////// imports //////////////

use arithmetic::table::{ArithTable, TableComm};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    timed,
    verifier::Verifier,
};
use ark_std::{end_timer, start_timer};
use derivative::Derivative;
use grouping_check::GroupingCheckPIOP;
use stat_check::StatCheckPIOP;
use std::marker::PhantomData;
use structs::GroupByConfig;

////////////// GroupBy prover //////////////

pub struct GroupByPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
pub struct GroupByProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_table: ArithTable<F, MvPCS, UvPCS>,
    pub output_table: ArithTable<F, MvPCS, UvPCS>,
    pub instr: GroupByConfig,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for GroupByProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        let input_table = self.input_table.deep_clone(prover.clone());
        let output_table = self.output_table.deep_clone(prover);
        Self {
            input_table,
            output_table,
            instr: self.instr.clone(),
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
pub struct GroupByVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub output_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub instr: GroupByConfig,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for GroupByPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = GroupByProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = GroupByVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // Honest prover check is not implemented for GroupByPIOP
        // as it is not required for the current use case.

        // TODO: Implement honest prover check for GroupByPIOP
        Ok(())
    }

    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // The first phase of GroupByPIOP is a PIOP to check if the output categories
        // are created correctly
        // Prepare the input for the grouping check
        let grouping_check_input = grouping_check::GroupingCheckProverInput {
            input_grouping_columns: input.input_table.get_cols(&input.instr.gpd_col_indices),
            output_grouping_columns: input.output_table.get_cols(&input.instr.gpd_col_indices),
        };
        let grouping_check_output = GroupingCheckPIOP::prove(prover, grouping_check_input)?;

        // The second phase of GroupByPIOP is a PIOP to check if the output stats for
        // each category is correct
        let stat_check_input = stat_check::StatCheckProverInput {
            query_output_table: input.output_table,
            query_input_table: input.input_table,
            input_folded_col: grouping_check_output.input_folded_col,
            output_folded_col: grouping_check_output.output_folded_col,
            super_set_multiplicity_tr_p: grouping_check_output.super_set_multiplicity_tr_p,
            instr: input.instr,
        };
        StatCheckPIOP::prove(prover, stat_check_input)?;
        Ok(())
    }

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // The first phase of GroupByPIOP is a PIOP to check if the output categories
        // are created correctly Prepare the input for the grouping check
        let grouping_check_input = grouping_check::GroupingCheckVerifierInput {
            input_grouping_column_comms: input.input_table_comm.cols(&input.instr.gpd_col_indices),
            output_grouping_column_comms: input
                .output_table_comm
                .cols(&input.instr.gpd_col_indices),
        };

        let grouping_check_output = GroupingCheckPIOP::verify(verifier, grouping_check_input)?;

        // The second phase of GroupByPIOP is a PIOP to check if the output stats for
        // each category is correct
        let stat_check_input = stat_check::StatCheckVerifierInput {
            super_set_multiplicity_tr_com: grouping_check_output.super_set_multiplicity_tr_com,
            input_folded_col_comm: grouping_check_output.input_folded_col_com,
            output_folded_col_comm: grouping_check_output.output_folded_col_com,
            query_output_table_comm: input.output_table_comm,
            query_input_table_comm: input.input_table_comm,
            instr: input.instr,
        };
        StatCheckPIOP::verify(verifier, stat_check_input)?;
        Ok(())
    }
}
