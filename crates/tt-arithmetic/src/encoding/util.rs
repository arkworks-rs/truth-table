use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

/// Compress arbitrary bytes to a 32-byte digest that serves as the canonical
/// field encoding for long strings and opaque binary values. Must be
/// collision-resistant: two inputs hashing equal are indistinguishable to
/// every downstream constraint (equality, joins, group-by), so a collision
/// would let a prover change query semantics while satisfying the proof.
#[inline]
pub(crate) fn hash_to_32_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[inline]
pub(crate) fn encode_hashed_bytes<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    let hash_bytes = hash_to_32_bytes(bytes);
    encode_bytes_to_fields::<F>(&hash_bytes)
}

pub(crate) fn field_element_byte_capacity<F: PrimeField>() -> usize {
    let bits = F::MODULUS_BIT_SIZE as usize;
    let bytes = bits.div_ceil(8);
    bytes.max(1)
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
