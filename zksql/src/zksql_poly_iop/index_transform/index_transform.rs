use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_inclusion::bag_inclusion::BagInclusionIOP, 
        index_transform::utils::{
            table_row_prover_agg, 
            table_row_verifier_agg,
            prover_sample_rand_powers,
            verifier_sample_rand_powers,
        },
    },
};

pub struct IndexTransformIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> IndexTransformIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        table_in: &Table<E, PCS>,
        table_out: &Table<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let rand_coeffs = prover_sample_rand_powers(prover_tracker, table_in.col_vals.len())?;
        let table_in_agg = table_row_prover_agg(table_in, &rand_coeffs)?;
        let table_out_agg = table_row_prover_agg(table_out, &rand_coeffs)?;
        BagInclusionIOP::<E, PCS>::prove(
            prover_tracker,
            &table_out_agg,
            &table_in_agg,
        )?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        table_in: &TableComm<E, PCS>,
        table_out: &TableComm<E, PCS>,
    )
    -> Result<(), PolyIOPErrors> {
        let rand_coeffs = verifier_sample_rand_powers(verifier_tracker, table_in.col_vals.len())?;
        let table_in_agg = table_row_verifier_agg(table_in, &rand_coeffs)?;
        let table_out_agg = table_row_verifier_agg(table_out, &rand_coeffs)?;
        BagInclusionIOP::<E, PCS>::verify(
            verifier_tracker,
            &table_out_agg,
            &table_in_agg,
        )?;

        Ok(())
    }
}