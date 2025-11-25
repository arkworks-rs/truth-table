#[cfg(feature = "honest-prover")]
use ark_ff::PrimeField;
use ark_ff::{Field, batch_inversion};
#[cfg(feature = "honest-prover")]
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::structs::polynomial::TrackedPoly,
};

pub fn invert_or_one_in_place<F: Field>(v: &mut [F]) {
    // Record which entries are zero before we mutate the slice.
    let zero_mask: Vec<bool> = v.iter().map(|x| x.is_zero()).collect();

    // Fast batch inversion: non-zeros become inverses; zeros stay zero.
    batch_inversion(v);

    // Set zeros to 1 as per your rule.
    for (x, was_zero) in v.iter_mut().zip(zero_mask.into_iter()) {
        if was_zero {
            *x = F::one();
        }
    }
}

#[cfg(feature = "honest-prover")]
pub(super) fn activators_match<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
>(
    lhs: Option<TrackedPoly<F, MvPCS, UvPCS>>,
    rhs: Option<TrackedPoly<F, MvPCS, UvPCS>>,
) -> bool {
    match (lhs, rhs) {
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => true,
        (Some(lhs_poly), Some(rhs_poly)) => {
            lhs_poly.log_size() == rhs_poly.log_size()
                && lhs_poly.evaluations() == rhs_poly.evaluations()
        }
    }
}
