use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_std::{One, Zero};
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std;

use super::{Col, PolyIOPErrors};

pub fn calc_supp_check_advice<F: PrimeField + PrimeField, PCS>(
    col: &Col<F, PCS>,
) -> Result<
    (
        DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
        DenseMultilinearExtension<F>,
    ),
    PolyIOPErrors,
>
// (supp, m)
where
    PCS: PolynomialCommitmentScheme<F>,
{
    let col_nv = col.num_vars();
    let col_len = 2_usize.pow(col_nv as u32);
    let col_poly_evals = col.inner_poly.evaluations();
    let col_sel_evals = col.actv_poly.evaluations();

    // sort ascending with col_sel = 0 at the end
    let mut indices: Vec<usize> = (0..col_len).collect();
    indices.sort_by(|&i, &j| {
        (col_sel_evals[j], col_poly_evals[i]).cmp(&(col_sel_evals[i], col_poly_evals[j]))
    });

    let mut reindexed_col_poly_evals = Vec::<F>::with_capacity(col_len);
    let mut reindexed_col_sel_evals = Vec::<F>::with_capacity(col_len);
    for i in 0..col_len {
        reindexed_col_poly_evals.push(col_poly_evals[indices[i]]);
        reindexed_col_sel_evals.push(col_sel_evals[indices[i]]);
    }

    // calculate the SUPP(col_a) and the corresponding multiplicity vector
    let mut temp_supp_evals = Vec::<F>::with_capacity(col_len);
    let mut temp_supp_sel_evals = Vec::<F>::with_capacity(col_len);
    let mut temp_multiplicities = Vec::<F>::with_capacity(col_len);
    let mut i = 0;

    // get the values of elements actually in the col and their multiplicities
    // push all the zero elements for col_sel = 0, replacing poly values with zero
    while i < indices.len() && col_sel_evals[indices[i]] != F::zero() {
        let val = col_poly_evals[indices[i]];
        let mut mult: u64 = 0;
        while i < indices.len()
            && col_sel_evals[indices[i]] != F::zero()
            && col_poly_evals[indices[i]] == val
        {
            mult += 1;
            i += 1;
        }
        temp_supp_evals.push(val);
        temp_supp_sel_evals.push(F::one());
        temp_multiplicities.push(F::from(mult));
    }
    // extend vectors to the correct length
    // putting zero values at the front for sorting
    let mut supp_evals = Vec::<F>::with_capacity(col_len);
    let mut supp_sel_evals = Vec::<F>::with_capacity(col_len);
    let mut multiplicities = Vec::<F>::with_capacity(col_len);
    supp_evals.extend(vec![F::zero(); col_len - temp_supp_evals.len()]);
    supp_sel_evals.extend(vec![F::zero(); col_len - temp_supp_sel_evals.len()]);
    multiplicities.extend(vec![F::zero(); col_len - temp_multiplicities.len()]);
    supp_evals.extend(temp_supp_evals.clone());
    supp_sel_evals.extend(temp_supp_sel_evals);
    multiplicities.extend(temp_multiplicities);

    // create the mles from the evaluation vectors
    let supp_mle = DenseMultilinearExtension::from_evaluations_vec(col_nv, supp_evals);
    let supp_sel_mle = DenseMultilinearExtension::from_evaluations_vec(col_nv, supp_sel_evals);
    let multiplicity_mle = DenseMultilinearExtension::from_evaluations_vec(col_nv, multiplicities);

    Ok((supp_mle, supp_sel_mle, multiplicity_mle))
}
