use ark_ff::{BigInteger, PrimeField};
use datafusion::arrow::datatypes::DataType;
use sha2::{Digest, Sha256};

/// The bytes of the SHA-256 digest a hashed value keeps. 31 bytes fit in one
/// slot of every supported field (see [`field_element_byte_capacity`]).
pub(crate) const HASH_BYTES: usize = 31;

/// The field encoding of a long string or an opaque binary value: its
/// digest truncated to [`HASH_BYTES`]. The hash must be collision-resistant:
/// two inputs hashing equal are indistinguishable to every constraint
/// (equality, joins, group-by), so a collision would let a prover change the
/// query's result.
#[inline]
pub(crate) fn encode_hashed_bytes<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    encode_bytes_to_fields::<F>(&digest[..HASH_BYTES])
}

/// The number of field elements a hashed value takes.
pub(crate) fn hash_slot_count<F: PrimeField>() -> usize {
    HASH_BYTES.div_ceil(field_element_byte_capacity::<F>())
}

/// `(0..n).map(f)` collected in order, in parallel when the `parallel`
/// feature is on.
pub(crate) fn map_indices<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync + Send) -> Vec<T> {
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        (0..n)
            .into_par_iter()
            .with_min_len(1 << 10)
            .map(f)
            .collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        (0..n).map(f).collect()
    }
}

/// The bytes one field element holds as an integer: `c` bytes stay below
/// `2^(8c) <= 2^(MODULUS_BIT_SIZE - 1) < p`, so the packing is injective and
/// a slot's integer value is the one its limbs recompose
/// ([`hash_slot_limb_widths`](super::hash_slot_limb_widths)).
pub(crate) fn field_element_byte_capacity<F: PrimeField>() -> usize {
    ((F::MODULUS_BIT_SIZE as usize - 1) / 8).max(1)
}

/// Whether a column of this type encodes each value as hash slots, each an
/// integer of at most [`field_element_byte_capacity`] bytes.
pub fn is_hashed_type(dtype: &DataType) -> bool {
    matches!(
        dtype,
        DataType::Utf8
            | DataType::LargeUtf8
            | DataType::Utf8View
            | DataType::Binary
            | DataType::LargeBinary
            | DataType::BinaryView
            | DataType::FixedSizeBinary(_)
    )
}

/// The bit widths of a hash slot's limbs, most significant first: 16-bit
/// limbs, led by an 8-bit one when the slot's width is not a multiple of 16.
/// Range-checked to these widths, the limbs of a slot are unique, as the
/// integer they recompose is below `p`.
pub fn hash_slot_limb_widths<F: PrimeField>() -> Vec<u32> {
    let bits = 8 * field_element_byte_capacity::<F>() as u32;
    let mut widths = Vec::with_capacity(bits.div_ceil(16) as usize);
    if !bits.is_multiple_of(16) {
        widths.push(bits % 16);
    }
    widths.extend(std::iter::repeat_n(16, (bits / 16) as usize));
    widths
}

/// A hash slot's limbs ([`hash_slot_limb_widths`]), most significant first.
pub fn hash_slot_limbs<F: PrimeField>(slot: F) -> Vec<u16> {
    let bytes = slot.into_bigint().to_bytes_le();
    let bit = |i: usize| bytes.get(i / 8).is_some_and(|b| (b >> (i % 8)) & 1 == 1);
    let mut low = 0usize;
    let mut limbs: Vec<u16> = hash_slot_limb_widths::<F>()
        .into_iter()
        .rev()
        .map(|width| {
            let limb =
                (0..width as usize).fold(0u16, |acc, i| acc | (u16::from(bit(low + i)) << i));
            low += width as usize;
            limb
        })
        .collect();
    limbs.reverse();
    limbs
}

pub(crate) fn encode_bytes_to_fields<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let chunk_size = field_element_byte_capacity::<F>();
    bytes
        .chunks(chunk_size)
        .map(|chunk| F::from_le_bytes_mod_order(chunk))
        .collect()
}

pub(crate) fn collect_by_columns<F: PrimeField, R>(rows: usize, mut row_fn: R) -> Vec<Vec<F>>
where
    R: FnMut(usize) -> Vec<F>,
{
    let mut columns: Vec<Vec<F>> = Vec::new();

    for idx in 0..rows {
        let row_fields = row_fn(idx);

        if columns.is_empty() && row_fields.is_empty() {
            columns.push(Vec::with_capacity(rows));
        }

        if columns.len() < row_fields.len() {
            let existing = columns.len();
            columns.resize_with(row_fields.len(), || Vec::with_capacity(rows));
            for column in columns.iter_mut().skip(existing) {
                column.resize(idx, F::zero());
            }
        }

        for (col_idx, column) in columns.iter_mut().enumerate() {
            let value = row_fields.get(col_idx).copied().unwrap_or_else(F::zero);
            column.push(value);
        }
    }

    if columns.is_empty() {
        vec![Vec::new()]
    } else {
        columns
    }
}
