use ark_ec::pairing::Pairing;
use std::collections::HashSet;
use std::vec;
use std::cmp::max;
use ark_std::{Zero, One};
use ark_poly::DenseMultilinearExtension;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::tracker::prelude::*;
use crate::zksql_poly_iop::util::prelude::bag_multiplicity_count;

/// Inputs: bag_a, bag_b, which the prover wishes to prove are disjoint
/// Outputs: bag_c, m_a, m_b, which the prover will use as advice to prove bag_a and bag_b are disjoint
pub fn calc_bag_disjoint_advice<E, PCS>(
    bag_a: &Bag<E, PCS>,
    bag_b: &Bag<E, PCS>,
) -> Result<(DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>), PolyIOPErrors>  // (sum, sum_sel, m_a, m_b)
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // count the mutliplicities of elements in bag_a and bag_b
    let a_mults_map = bag_multiplicity_count(bag_a);
    let b_mults_map = bag_multiplicity_count(bag_b);

    // calculate bag_c, the sorted Supp(bag_a \Mutlisetsum bag_b)
    let bag_sum_nv = max(bag_a.num_vars(), bag_b.num_vars()) + 1;
    let bag_sum_len = 2_usize.pow(bag_sum_nv as u32);
    let mut sum_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    let mut sum_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    let mut sum_evals_map = HashSet::<E::ScalarField>::new();
    for val in a_mults_map.keys() {
        sum_evals_map.insert(val.clone());
    }
    for val in b_mults_map.keys() {
        sum_evals_map.insert(val.clone());
    }
    let mut unique_vals: Vec<E::ScalarField> = sum_evals_map.into_iter().collect();
    unique_vals.sort();
    sum_sel_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - unique_vals.len()]);
    sum_sel_evals.extend(vec![E::ScalarField::one(); unique_vals.len()]);
    sum_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - unique_vals.len()]);
    sum_evals.extend(unique_vals.clone());


    // calculate multiplicity vectors for bag_a and bag_b relative to bag_c
    let mut a_mults_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    let mut b_mults_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    a_mults_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - unique_vals.len()]);
    b_mults_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - unique_vals.len()]);
    for i in 0..unique_vals.len() {
        let val = unique_vals[i];
        let a_mult = E::ScalarField::from(*a_mults_map.get(&val).unwrap_or(&0));
        let b_mult = E::ScalarField::from(*b_mults_map.get(&val).unwrap_or(&0));
        a_mults_evals.push(a_mult);
        b_mults_evals.push(b_mult);
    }

    // create the mles from the evaluation vectors
    let sum_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_evals);
    let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_sel_evals);
    let sum_a_mult_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, a_mults_evals);
    let sum_b_mult_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, b_mults_evals);

    Ok((sum_mle, sum_sel_mle, sum_a_mult_mle, sum_b_mult_mle))
}