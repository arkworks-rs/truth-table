use arithmetic::{ark_ff, ark_poly};
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_std::{One, Zero};
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use kit::ark_std;
use std::{cmp::max, collections::HashSet, vec};

use crate::{
    col_toolbox::util::prelude::col_multiplicity_count,
};

use super::{Col, PolyIOPErrors};

/// Inputs: col_a, col_b, which the prover wishes to prove are disjoint
/// Outputs: col_c, m_a, m_b, which the prover will use as advice to prove col_a
/// and col_b are disjoint
pub fn calc_disjoint_check_advice<F, PCS>(
    col_a: &Col<F, PCS>,
    col_b: &Col<F, PCS>,
) -> Result<
    (
        DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
    ),
    PolyIOPErrors,
>
// (sum, sum_sel, m_a, m_b)
where
    F: PrimeField + PrimeField,
    PCS: PolynomialCommitmentScheme<F>,
{
    // count the mutliplicities of elements in col_a and col_b
    let a_mults_map = col_multiplicity_count(col_a);
    let b_mults_map = col_multiplicity_count(col_b);

    // calculate col_c, the sorted Supp(col_a \Mutlisetsum col_b)
    let col_sum_nv = max(col_a.num_vars(), col_b.num_vars()) + 1;
    let col_sum_len = 2_usize.pow(col_sum_nv as u32);
    let mut sum_evals = Vec::<F>::with_capacity(col_sum_len);
    let mut sum_sel_evals = Vec::<F>::with_capacity(col_sum_len);
    let mut sum_evals_map = HashSet::<F>::new();
    for val in a_mults_map.keys() {
        sum_evals_map.insert(val.clone());
    }
    for val in b_mults_map.keys() {
        sum_evals_map.insert(val.clone());
    }
    let mut unique_vals: Vec<F> = sum_evals_map.into_iter().collect();
    unique_vals.sort();
    sum_sel_evals.extend(vec![F::zero(); col_sum_len - unique_vals.len()]);
    sum_sel_evals.extend(vec![F::one(); unique_vals.len()]);
    sum_evals.extend(vec![F::zero(); col_sum_len - unique_vals.len()]);
    sum_evals.extend(unique_vals.clone());

    // calculate multiplicity vectors for col_a and col_b relative to col_c
    let mut a_mults_evals = Vec::<F>::with_capacity(col_sum_len);
    let mut b_mults_evals = Vec::<F>::with_capacity(col_sum_len);
    a_mults_evals.extend(vec![F::zero(); col_sum_len - unique_vals.len()]);
    b_mults_evals.extend(vec![F::zero(); col_sum_len - unique_vals.len()]);
    for i in 0..unique_vals.len() {
        let val = unique_vals[i];
        let a_mult = F::from(*a_mults_map.get(&val).unwrap_or(&0));
        let b_mult = F::from(*b_mults_map.get(&val).unwrap_or(&0));
        a_mults_evals.push(a_mult);
        b_mults_evals.push(b_mult);
    }

    // create the mles from the evaluation vectors
    let sum_mle = DenseMultilinearExtension::from_evaluations_vec(col_sum_nv, sum_evals);
    let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(col_sum_nv, sum_sel_evals);
    let sum_a_mult_mle = DenseMultilinearExtension::from_evaluations_vec(col_sum_nv, a_mults_evals);
    let sum_b_mult_mle = DenseMultilinearExtension::from_evaluations_vec(col_sum_nv, b_mults_evals);

    Ok((sum_mle, sum_sel_mle, sum_a_mult_mle, sum_b_mult_mle))
}
