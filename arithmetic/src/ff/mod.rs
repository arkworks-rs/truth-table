#[cfg(test)]
mod test;
use ark_ff::{BigInt, Field, PrimeField};

pub fn sort_permute_ff<F: PrimeField>(vec: &[F], actvtr: &[F]) -> (Vec<F>, Vec<usize>, Vec<usize>) {
    // Create a vector of indices
    let mut permutation: Vec<usize> = (0..vec.len()).collect();

    // Sort the indices based on the values in the input vector,
    // breaking ties using the tiebreaker vector
    permutation.sort_by(|&i, &j| {
        vec[i]
            .cmp(&vec[j]) // Primary sorting criterion
            .then(actvtr[i].cmp(&actvtr[j])) // Tie-breaking
    });

    // Create the sorted vector using the sorted indices
    let sorted_vec: Vec<F> = permutation.iter().map(|&i| vec[i]).collect();

    // Compute the inverse permutation
    let mut inverse_permutation = vec![0; vec.len()];
    for (sorted_idx, &orig_idx) in permutation.iter().enumerate() {
        inverse_permutation[orig_idx] = sorted_idx;
    }
    dbg!(vec);
    dbg!(&sorted_vec);
    dbg!(&permutation);
    dbg!(&inverse_permutation);
    (sorted_vec, permutation, inverse_permutation)
}

// Convert a vector of anything to a vector of field elements
#[macro_export]
macro_rules! to_field_vec {
    ($vec:expr, $field:ty) => {
        $vec.iter()
            .map(|x| <$field>::from(*x as u64))
            .collect::<Vec<$field>>()
    };
}
