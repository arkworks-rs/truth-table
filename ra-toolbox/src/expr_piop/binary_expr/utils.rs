use ark_ff::{Field, batch_inversion};

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
