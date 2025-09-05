//! A PIOP for checking if a selection operation ($\sigma$) was done correctly
//!
//! More precisely, this PIOP, given the input and ouput tables of a selection
//! operation, checks if the output table is a correct subset of the input table
//! based on the selection criteria provided.

///////////////// Modules /////////////////
pub mod honest_prover;
pub mod selection_check;
pub mod structs;
#[cfg(test)]
mod test;
////////////// imports //////////////

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    timed,
    verifier::Verifier,
};
use ark_std::{end_timer, start_timer};
use col_toolbox::binary_check::{
    BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput,
};
use selection_check::{SelectionCheckProverInput, SelectionCheckVerifierInput};
use std::marker::PhantomData;
use structs::{SelectProverInput, SelectVerifierInput};

use ark_piop::errors::SnarkResult;
////////////// Select prover //////////////

pub struct SelectCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for SelectCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = SelectProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = SelectVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        Self::honest_prover_check_helper(input)
    }

    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // First check the output column activator is valid or not
        let binary_check_input = BinaryCheckProverInput {
            activator: input
                .output_table
                .actvtr_poly()
                .as_ref()
                .unwrap()
                .clone(),
        };
        BinaryCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, binary_check_input)?;
        //////////// Check the selection was done correctly ////////////

        let selection_check_prover_input = SelectionCheckProverInput {
            query_input_table: input.input_table.clone(),
            query_output_table: input.output_table.clone(),
            select_conf: input.select_conf.clone(),
        };
        selection_check::SelectionCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            selection_check_prover_input,
        )?;
        Ok(())
    }

    #[timed]
    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let binary_check_input = BinaryCheckVerifierInput {
            activator_comm: input
                .output_table_comm
                .actvtr_poly()
                .as_ref()
                .unwrap()
                .clone(),
        };

        BinaryCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, binary_check_input)?;

        //////////// Check the selection was done correctly ////////////
        let selection_check_verifier_input = SelectionCheckVerifierInput {
            query_input_table_comm: input.input_table_comm.clone(),
            query_output_table_comm: input.output_table_comm.clone(),
            select_conf: input.select_conf.clone(),
        };
        selection_check::SelectionCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            selection_check_verifier_input,
        )?;
        Ok(())
    }
}
