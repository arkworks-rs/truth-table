use std::collections::HashMap;
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::Zero;
use crate::tracker::prelude::Bag;
use crate::subroutines::PolynomialCommitmentScheme;

// Returns a map from the unique evaluations of bag to their multiplicities
// does not include values where the selector is zero
pub fn vec_multiplicity_count<E>(
    poly: &Vec::<E::ScalarField>,
    sel: &Vec::<E::ScalarField>,
) -> HashMap<E::ScalarField, u64>
where
    E: Pairing
{
    let mut mults_map = HashMap::<E::ScalarField, u64>::new();
    for i in 0..poly.len() {
        if sel[i] == E::ScalarField::zero() {
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

pub fn bag_multiplicity_count<E, PCS>(
    bag: &Bag<E, PCS>,
) -> HashMap<E::ScalarField, u64>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let poly_evals = bag.poly.evaluations();
    let sel_evals = bag.selector.evaluations();
    vec_multiplicity_count::<E>(&poly_evals, &sel_evals)
}

pub fn mle_multiplicity_count<E>(
    poly: &DenseMultilinearExtension<E::ScalarField>,
    sel: &DenseMultilinearExtension<E::ScalarField>,
) -> HashMap<E::ScalarField, u64>
where
    E: Pairing
{
    let poly_evals = poly.evaluations.clone();
    let sel_evals = sel.evaluations.clone();
    vec_multiplicity_count::<E>(&poly_evals, &sel_evals)
}

