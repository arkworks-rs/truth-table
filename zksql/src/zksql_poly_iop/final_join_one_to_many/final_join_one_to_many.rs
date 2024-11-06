
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        index_transform::index_transform::IndexTransformIOP,
        final_join_one_to_many::utils::{calc_final_join_one_to_many_index_transform, calc_index_transformed_bag},
    },
};

pub struct FinalJoinOneToManyIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> FinalJoinOneToManyIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        table_a: &Table<E, PCS>, // primary key table, no duplicates
        table_b: &Table<E, PCS>, // foreign key table, has duplicates
        a_join_col_index: usize,
        b_join_col_index: usize,
    ) -> Result<Table<E, PCS>, PolyIOPErrors> {
        // calculate the mles needed for the result table
        // calculate the index transform that should be applied to table_a to get rows of the result table 
        let a_index_transform = calc_final_join_one_to_many_index_transform(table_a, table_b, a_join_col_index, b_join_col_index)?;
        // calculate the columns of the result table that come from table_a by applying the index transform
        let mut res_table_a_mles = Vec::<DenseMultilinearExtension<E::ScalarField>>::with_capacity(table_a.col_vals.len());
        for a_col in table_a.col_vals.iter() {
            res_table_a_mles.push(calc_index_transformed_bag(&a_index_transform, a_col, &table_b.selector)?);
        }

        // put res_table_a_mles into the prover tracker
        let mut transformed_a_cols = Vec::<TrackedPoly<E, PCS>>::with_capacity(table_a.col_vals.len());
        for col_mle in res_table_a_mles.iter() {
            transformed_a_cols.push(prover_tracker.track_and_commit_poly(col_mle.clone())?);
        }

        // invoke the gadget IOPs to prove the result table is correct
        let res_table = FinalJoinOneToManyIOP::prove_with_advice(
            prover_tracker,
            table_a,
            table_b,
            a_join_col_index,
            b_join_col_index,
            &transformed_a_cols,
        )?;

        Ok(res_table)
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        table_a: &Table<E, PCS>, // primary key table, no duplicates
        table_b: &Table<E, PCS>, // foreign key table, has duplicates
        a_join_col_index: usize,
        b_join_col_index: usize,
        transformed_a_cols: &Vec::<TrackedPoly<E, PCS>>,
    ) -> Result<Table<E, PCS>, PolyIOPErrors> {
        // sanity check that the table_a join_col does not have duplicates, since the IOP is not sound otherwise
        #[cfg(debug_assertions)] 
        {
            let table_a_join_col_evals = table_a.col_vals[a_join_col_index].evaluations();
            let mut counts = HashMap::<E::ScalarField, usize>::new();
            for i in 0..table_a_join_col_evals.len() {
                let val = table_a_join_col_evals[i];
                let count = counts.entry(val).or_insert(0);
                *count += 1;
            }
            for (_, count) in counts.iter() {
                if *count > 1 {
                    return Err(PolyIOPErrors::InvalidParameters(format!("FinalJoinOneToManyIOP Error: table_a join_col has duplicates")));
                }
            }
        }

        // set up the result table
        let mut res_table_col_polys = transformed_a_cols.clone();
        res_table_col_polys.append(&mut table_b.col_vals.clone());
        let res_table = Table::new(res_table_col_polys, table_b.selector.clone());

        // invoke the index transform IOP to show the rows of the result table come from index_transformed rows of table_a
        let transformed_a_cols = res_table.col_vals.clone()[..table_a.col_vals.len()].to_vec();
        let transformed_a_table = Table::new(transformed_a_cols, res_table.selector.clone());
        IndexTransformIOP::<E, PCS>::prove(
            prover_tracker,
            table_a,
            &transformed_a_table,
        )?;

        // invoke the zero check IOP for the claim that the join columns are equal on the boolean hypercube
        let join_col_a = res_table.col_vals[a_join_col_index].clone();
        let join_col_b = res_table.col_vals[table_a.col_vals.len() + b_join_col_index].clone();
        let equality_check_poly = join_col_a.sub_poly(&join_col_b).mul_poly(&res_table.selector.clone());
        prover_tracker.add_zerocheck_claim(equality_check_poly.id);
        
        Ok(res_table)
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        table_a: &TableComm<E, PCS>, // primary key table, no duplicates
        table_b: &TableComm<E, PCS>, // foreign key table, has duplicates
        a_join_col_index: usize,
        b_join_col_index: usize,
    ) -> Result<TableComm<E, PCS>, PolyIOPErrors> {
        // tranfer trackerIDs for the transformed_a_cols to the verifier tracker
        let mut transformed_a_cols = Vec::<TrackedComm<E, PCS>>::with_capacity(table_a.col_vals.len());
        for _ in table_a.col_vals.iter() {
            let next_id = verifier_tracker.get_next_id();
            transformed_a_cols.push(verifier_tracker.transfer_prover_comm(next_id));
        }

        // invoke the gadget IOPs to prove the result table is correct
        let res_table = FinalJoinOneToManyIOP::verify_with_advice(
            verifier_tracker,
            table_a,
            table_b,
            a_join_col_index,
            b_join_col_index,
            &transformed_a_cols,
        )?;

        Ok(res_table)
    }

    pub fn verify_with_advice(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        table_a: &TableComm<E, PCS>, // primary key table, no duplicates
        table_b: &TableComm<E, PCS>, // foreign key table, has duplicates
        a_join_col_index: usize,
        b_join_col_index: usize,
        transformed_a_cols: &Vec::<TrackedComm<E, PCS>>,
    ) -> Result<TableComm<E, PCS>, PolyIOPErrors> {
        // set up the result table
        let mut res_table_col_polys = transformed_a_cols.clone();
        res_table_col_polys.append(&mut table_b.col_vals.clone());
        let res_table = TableComm::new(res_table_col_polys, table_b.selector.clone(), table_b.num_vars());

        // invoke the index transform IOP to show the rows of the result table come from index_transformed rows of table_a
        let transformed_a_cols = res_table.col_vals.clone()[..table_a.col_vals.len()].to_vec();
        let transformed_a_table = TableComm::new(transformed_a_cols, res_table.selector.clone(), res_table.num_vars());
        IndexTransformIOP::<E, PCS>::verify(
            verifier_tracker,
            table_a,
            &transformed_a_table,
        )?;

        // invoke the zero check IOP for the claim that the join columns are equal on the boolean hypercube
        let join_col_a = res_table.col_vals[a_join_col_index].clone();
        let join_col_b = res_table.col_vals[table_a.col_vals.len() + b_join_col_index].clone();
        let equality_check_poly = join_col_a.sub_comms(&join_col_b).mul_comms(&res_table.selector.clone());
        verifier_tracker.add_zerocheck_claim(equality_check_poly.id);

        Ok(res_table)
    }
}