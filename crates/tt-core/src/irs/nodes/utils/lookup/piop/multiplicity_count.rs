use ark_ff::PrimeField;
use indexmap::IndexMap;

/// A map from the distinct values of `poly` to their multiplicities, skipping
/// the rows where the selector is zero.
pub fn vec_multiplicity_count<F>(poly: &[F], sel: Option<&[F]>) -> IndexMap<F, u64>
where
    F: PrimeField,
{
    let mut mults_map = IndexMap::<F, u64>::new();

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
