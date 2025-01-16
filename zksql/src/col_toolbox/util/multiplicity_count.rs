use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_std::Zero;
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std;
use std::collections::HashMap;

use crate::tracker::prelude::Col;

// Returns a map from the unique evaluations of col to their multiplicities
// does not include values where the selector is zero
pub fn vec_multiplicity_count<F>(poly: &Vec<F>, sel: &Vec<F>) -> HashMap<F, u64>
where
    F: PrimeField + PrimeField,
{
    let mut mults_map = HashMap::<F, u64>::new();
    for i in 0..poly.len() {
        if sel[i] == F::zero() {
            continue;
        }
        let val = poly[i];
        let get_res = mults_map.get(&val);
        if get_res.is_none() {
            mults_map.insert(val, 1);
        } else {
            let mult = get_res.unwrap() + 1;
            mults_map.insert(val, mult);
        }
    }
    mults_map
}

pub fn col_multiplicity_count<F, PCS>(col: &Col<F, PCS>) -> HashMap<F, u64>
where
    F: PrimeField + PrimeField,
    PCS: PolynomialCommitmentScheme<F>,
{
    let poly_evals = col.inner_poly.evaluations();
    let sel_evals = col.actv_poly.evaluations();
    vec_multiplicity_count::<F>(&poly_evals, &sel_evals)
}

pub fn mle_multiplicity_count<F: PrimeField + PrimeField>(
    poly: &DenseMultilinearExtension<F>,
    sel: &DenseMultilinearExtension<F>,
) -> HashMap<F, u64> {
    let poly_evals = poly.evaluations.clone();
    let sel_evals = sel.evaluations.clone();
    vec_multiplicity_count::<F>(&poly_evals, &sel_evals)
}
