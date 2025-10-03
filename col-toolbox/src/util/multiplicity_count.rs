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

pub fn col_multiplicity_count<F, MvPCS, UvPCS>(col: &TrackedCol<F, MvPCS, UvPCS>) -> HashMap<F, u64>
where
    F: PrimeField + PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let poly_evals = col.data_poly().evaluations();
    match col.actvtr_poly() {
        Some(ref sel) => vec_multiplicity_count::<F>(&poly_evals, Some(&sel.evaluations())),
        None => vec_multiplicity_count::<F>(&poly_evals, None),
    }
}

pub fn mle_multiplicity_count<F: PrimeField + PrimeField>(
    poly: &MLE<F>,
    sel: &Option<MLE<F>>,
) -> HashMap<F, u64> {
    let poly_evals = poly.evaluations().clone();
    match sel {
        Some(sel) => vec_multiplicity_count::<F>(&poly_evals, Some(&sel.evaluations())),
        None => vec_multiplicity_count::<F>(&poly_evals, None),
    }
}
