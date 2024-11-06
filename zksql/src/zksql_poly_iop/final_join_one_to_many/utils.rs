use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::One;
use ark_std::Zero;
use std::collections::HashMap;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::tracker::prelude::*;

// Calculate the index transform that should be applied to table_a to get rows of the result table 
// returns a list of indices I such that 
// I[x] = y means that the xth element of the transformed row should come from the yth row of table_a
pub fn calc_final_join_one_to_many_index_transform<E, PCS>(
    table_a: &Table<E, PCS>, // primary key table, no duplicates
    table_b: &Table<E, PCS>, // foreign key table, has duplicates
    a_join_col_index: usize,
    b_join_col_index: usize,
) -> Result<Vec<usize>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // create a hashmap from the values of the table_a join column to their index in the table_a
    let mut a_join_col_hashmap: HashMap<E::ScalarField, usize> = HashMap::new();
    let a_join_col_evals = table_a.col_vals[a_join_col_index].evaluations();
    let a_sel_evals = table_a.selector.evaluations();
    for i in 0..a_join_col_evals.len() {
        if a_sel_evals[i] == E::ScalarField::one() { // only include activated rows
            let val = a_join_col_evals[i];
            a_join_col_hashmap.insert(val, i);
        }
    }

    // iterate through the table_b col vals and get the index of the matching row in table_a
    let b_join_col_evals = table_b.col_vals[b_join_col_index].evaluations();
    let b_sel_evals = table_b.selector.evaluations();
    let table_b_col_len = b_join_col_evals.len();
    let mut index_transform = Vec::<usize>::with_capacity(table_b_col_len);
    for i in 0..table_b_col_len {
        if b_sel_evals[i] == E::ScalarField::one() { // only include activated rows
            let b_val = b_join_col_evals[i];
            let a_index = a_join_col_hashmap.get(&b_val);
            if a_index.is_none() {
                return Err(PolyIOPErrors::InvalidParameters(format!("FinalJoinOneToManyIOP Error: b_join_col_index {} does not match any row in table_a", b_join_col_index)));
            }
            index_transform.push(*a_index.unwrap());
        } else {
            index_transform.push(0); // row not activated, so put in a dummy index
        }
    }

    Ok(index_transform)
}

pub fn calc_index_transformed_bag<E, PCS>(
    index_transform: &Vec<usize>,
    old_poly: &TrackedPoly<E, PCS>,
    new_activator: &TrackedPoly<E, PCS>,
) -> Result<DenseMultilinearExtension<E::ScalarField>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let old_poly_evals = old_poly.evaluations();
    let new_activator_evals = new_activator.evaluations();
    let new_len = index_transform.len();

    #[cfg(debug_assertions)] 
    {
        assert_eq!(new_activator_evals.len(), new_len);
    }
    
    let mut transformed_poly_evals = Vec::<E::ScalarField>::with_capacity(new_len);
    for i in 0..new_len {
        if new_activator_evals[i] == E::ScalarField::one() {
            transformed_poly_evals.push(old_poly_evals[index_transform[i]]);
        } else {
            transformed_poly_evals.push(E::ScalarField::zero());
        }
    }

    let new_mle = DenseMultilinearExtension::from_evaluations_vec(new_activator.num_vars(), transformed_poly_evals);
    
    Ok(new_mle)
}