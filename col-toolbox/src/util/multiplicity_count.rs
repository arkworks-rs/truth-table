use arithmetic::col::TrackedCol;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use std::collections::HashMap;

// Returns a map from the unique evaluations of col to their multiplicities
// does not include values where the selector is zero
pub fn vec_multiplicity_count<F>(poly: &[F], sel: Option<&[F]>) -> HashMap<F, u64>
where
    F: PrimeField,
{
    let mut mults_map = HashMap::<F, u64>::new();

    if let Some(sel) = sel {
        for (i, &val) in poly.iter().enumerate() {
            if sel[i] == F::zero() {
                continue;
            }
            *mults_map.entry(val).or_insert(0) += 1;
        }
    } else {
        for &val in poly {
            *mults_map.entry(val).or_insert(0) += 1;
        }
    }

    mults_map
}


