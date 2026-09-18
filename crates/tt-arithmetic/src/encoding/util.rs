use ark_ff::PrimeField;
use datafusion::arrow::datatypes::{DataType, IntervalUnit};
use sha2::{Digest, Sha256};

use crate::errors::EncodeError;

/// Require a fixed-width bit pattern to fit below the modulus before using
/// the current field encoding.
///
/// A prime whose modulus has at most `source_bits` bits is strictly smaller
/// than `2^source_bits`, so modular conversion can identify two distinct
/// source patterns. A future range-checked multi-limb encoding could support
/// smaller fields; until then this conservative guard fails closed. The
/// strict inequality also handles a modulus bit size exactly equal to the
/// source width.
pub(crate) fn require_modulus_wider_than<F: PrimeField>(
    source_bits: u32,
    source_type: &'static str,
) -> Result<(), EncodeError> {
    if F::MODULUS_BIT_SIZE <= source_bits {
        return Err(EncodeError::TypeNotSupported(format!(
            "{source_type} requires a field modulus wider than {source_bits} bits"
        )));
    }
    Ok(())
}

/// Validate fixed-width encodings whose source representation can exceed the
/// proof field.
///
/// This is shared by direct value encoding, top-level dispatch, and
/// schema-only verifier tracking. Checking only [`super::Encodable::encode`]
/// would stop an honest prover but still let a verifier interpret a
/// maliciously supplied commitment as an unsupported column.
///
/// This is a safety preflight, not a comprehensive Arrow support check:
/// success does not imply that an [`super::Encodable`] implementation exists
/// for the type.
pub fn validate_fixed_width_encoding_safety<F: PrimeField>(
    data_type: &DataType,
) -> Result<(), EncodeError> {
    match data_type {
        DataType::Decimal256(..) => require_modulus_wider_than::<F>(256, "Decimal256"),
        DataType::Decimal128(..) => require_modulus_wider_than::<F>(128, "Decimal128"),
        DataType::Interval(IntervalUnit::MonthDayNano) => {
            require_modulus_wider_than::<F>(128, "IntervalMonthDayNano")
        }
        DataType::List(field)
        | DataType::ListView(field)
        | DataType::FixedSizeList(field, _)
        | DataType::LargeList(field)
        | DataType::LargeListView(field)
        | DataType::Map(field, _) => validate_fixed_width_encoding_safety::<F>(field.data_type()),
        DataType::Struct(fields) => fields
            .iter()
            .try_for_each(|field| validate_fixed_width_encoding_safety::<F>(field.data_type())),
        DataType::Union(fields, _) => fields.iter().try_for_each(|(_type_id, field)| {
            validate_fixed_width_encoding_safety::<F>(field.data_type())
        }),
        DataType::Dictionary(key_type, value_type) => {
            validate_fixed_width_encoding_safety::<F>(key_type)?;
            validate_fixed_width_encoding_safety::<F>(value_type)
        }
        DataType::RunEndEncoded(run_ends, values) => {
            validate_fixed_width_encoding_safety::<F>(run_ends.data_type())?;
            validate_fixed_width_encoding_safety::<F>(values.data_type())
        }
        _ => Ok(()),
    }
}

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
