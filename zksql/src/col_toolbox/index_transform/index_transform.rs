use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use crate::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    col_toolbox::{
        inclusion_check::InclusionCheck, 
        index_transform::utils::{
            table_row_prover_agg, 
            table_row_verifier_agg,
            prover_sample_rand_powers,
            verifier_sample_rand_powers,
        },
    },
};

pub struct IndexTransformIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(PhantomData<F>, PhantomData<PCS>);
impl <F:PrimeField, PCS: PolynomialCommitmentScheme<F>> IndexTransformIOP<F, PCS> 
where PCS: PolynomialCommitmentScheme<F> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        table_in: &Table<F, PCS>,
        table_out: &Table<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let rand_coeffs = prover_sample_rand_powers(prover_tracker, table_in.col_vals.len())?;
        let table_in_agg = table_row_prover_agg(table_in, &rand_coeffs)?;
        let table_out_agg = table_row_prover_agg(table_out, &rand_coeffs)?;
        InclusionCheck::<F, PCS>::prove(
            prover_tracker,
            &table_out_agg,
            &table_in_agg,
        )?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        table_in: &TableComm<F, PCS>,
        table_out: &TableComm<F, PCS>,
    )
    -> Result<(), PolyIOPErrors> {
        let rand_coeffs = verifier_sample_rand_powers(verifier_tracker, table_in.col_vals.len())?;
        let table_in_agg = table_row_verifier_agg(table_in, &rand_coeffs)?;
        let table_out_agg = table_row_verifier_agg(table_out, &rand_coeffs)?;
        InclusionCheck::<F, PCS>::verify(
            verifier_tracker,
            &table_out_agg,
            &table_in_agg,
        )?;

        Ok(())
    }
}