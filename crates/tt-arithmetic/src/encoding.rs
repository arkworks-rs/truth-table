///////// Imports /////////
use crate::errors::EncodeError;
use ark_ff::PrimeField;
use datafusion::arrow::{
    array::{
        Array, ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Date64Array,
        Decimal128Array, Decimal256Array, DictionaryArray, DurationMicrosecondArray,
        DurationMillisecondArray, DurationNanosecondArray, DurationSecondArray,
        FixedSizeBinaryArray, FixedSizeListArray, Float16Array, Float32Array, Float64Array,
        Int8Array, Int8DictionaryArray, Int16Array, Int16DictionaryArray, Int16RunArray,
        Int32Array, Int32DictionaryArray, Int32RunArray, Int64Array, Int64DictionaryArray,
        Int64RunArray, IntervalDayTimeArray, IntervalMonthDayNanoArray, IntervalYearMonthArray,
        LargeBinaryArray, LargeListArray, LargeListViewArray, LargeStringArray, ListArray,
        ListViewArray, MapArray, NullArray, StringArray, StringViewArray, StructArray,
        Time32MillisecondArray, Time32SecondArray, Time64MicrosecondArray, Time64NanosecondArray,
        TimestampMicrosecondArray, TimestampMillisecondArray, TimestampNanosecondArray,
        TimestampSecondArray, UInt8Array, UInt8DictionaryArray, UInt16Array, UInt16DictionaryArray,
        UInt32Array, UInt32DictionaryArray, UInt64Array, UInt64DictionaryArray, UnionArray,
    },
    datatypes::{DataType, IntervalUnit, TimeUnit},
};
use datafusion_common::ScalarValue;

/// A named slice of a column's encoded representation. A single Arrow column
/// may expand into multiple `EncodedSegment`s — e.g. strings become
/// `[primary hash, "__length", "__chars"]`. The first segment of each Arrow
/// column conventionally carries an empty `suffix` (so it inherits the source
/// column's name); additional segments use a role-specific suffix (e.g.
/// `__length`, `__chars`) or an auto-numbered `__enc<N>` when the role is
/// generic.
///
/// Segments default to the **row domain** — they share the source table's
/// row count and the table-level `__activator__`. A segment may opt into a
/// **side domain** by setting `side: Some(SideSegmentInfo)`; side segments
/// live on their own multilinear domain with their own contiguous-one
/// activator, derived from `active_len` (see [`SideSegmentInfo`]).
#[derive(Debug, Clone)]
pub struct EncodedSegment<F: PrimeField> {
    pub suffix: String,
    pub values: Vec<F>,
    pub side: Option<SideSegmentInfo>,
}

/// Payload + sizing metadata for a side-domain segment. The segment's raw
/// data is carried here as `bytes` (one byte per slot, pow2-padded by the
/// caller) so it can stay 32× smaller than the field-element form used by
/// row-domain segments. `active_len` is the count of leading non-padding
/// entries; the side activator is a contiguous-one polynomial of that
/// weight that downstream callers materialize on demand.
#[derive(Debug, Clone)]
pub struct SideSegmentInfo {
    pub bytes: Vec<u8>,
    pub active_len: usize,
}

impl<F: PrimeField> EncodedSegment<F> {
    pub fn primary(values: Vec<F>) -> Self {
        Self {
            suffix: String::new(),
            values,
            side: None,
        }
    }

    pub fn named(suffix: impl Into<String>, values: Vec<F>) -> Self {
        Self {
            suffix: suffix.into(),
            values,
            side: None,
        }
    }

    /// Construct a side-domain segment. `bytes` carries the raw byte values
    /// of the segment (already pow2-padded by the caller), and `active_len`
    /// is the count of active (non-padding) leading entries. The
    /// row-domain `values` field is left empty for side segments.
    pub fn side(suffix: impl Into<String>, bytes: Vec<u8>, active_len: usize) -> Self {
        debug_assert!(
            active_len <= bytes.len(),
            "side segment active_len {} exceeds bytes length {}",
            active_len,
            bytes.len()
        );
        Self {
            suffix: suffix.into(),
            values: Vec::new(),
            side: Some(SideSegmentInfo { bytes, active_len }),
        }
    }

    pub fn is_side(&self) -> bool {
        self.side.is_some()
    }
}

/// Wrap a `Vec<Vec<F>>` (one inner Vec per column) into auto-named segments:
/// the first segment uses no suffix, subsequent segments get `__enc1`,
/// `__enc2`, … This is the default naming when an encoder does not assign
/// role-specific names.
pub(crate) fn auto_segments<F: PrimeField>(cols: Vec<Vec<F>>) -> Vec<EncodedSegment<F>> {
    cols.into_iter()
        .enumerate()
        .map(|(i, values)| {
            let suffix = if i == 0 {
                String::new()
            } else {
                format!("__enc{i}")
            };
            EncodedSegment {
                suffix,
                values,
                side: None,
            }
        })
        .collect()
}

/// This macro implements the `Encodable` trait for Arrow array types that can
/// be mapped directly to field elements. No decoding functionality is provided
/// (or needed) for now.
macro_rules! impl_col_adapter_map {
    ($array_ty:ty, $map:expr_2021) => {
        impl<F: PrimeField> Encodable<F> for $array_ty {
            fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
                let cols = collect_by_columns(self.len(), |idx| {
                    if self.is_null(idx) {
                        vec![F::zero()]
                    } else {
                        vec![$map(self.value(idx))]
                    }
                });
                Ok(auto_segments(cols))
            }

            fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
                todo!("Decoding {} is not implemented yet", stringify!($array_ty));
            }
        }
    };
}
/// This macro implements the `Encodable` trait for Arrow array types that are
/// not supported yet
macro_rules! impl_col_adapter_unsupported {
    ($array_ty:ty, $name:expr_2021) => {
        impl<F: PrimeField> Encodable<F> for $array_ty {
            fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
                Err(EncodeError::TypeNotSupported($name.to_string()))
            }

            fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
                todo!("Decoding {} is not implemented yet", stringify!($array_ty));
            }
        }
    };
}

/// A trait for encoding types into PrimeField elements.
pub trait Encodable<F: PrimeField>: Sized {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError>;
    fn decode(field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError>;
}

/// Conventional segment suffix for the byte length of a string column.
pub const STRING_LENGTH_SUFFIX: &str = "__length";

/// Conventional segment suffix for the concatenated-characters side polynomial
/// of a string column. Each entry is the byte value (`F::from(byte as u64)`)
/// of one character. Bytes of active strings are laid out contiguously in
/// row order at the start of the polynomial, then zero-padded to the next
/// power of two. The accompanying side activator is a contiguous-one poly
/// with `active_len = sum of active string byte lengths`.
pub const STRING_CHARS_SUFFIX: &str = "__chars";

/// Returns the source-column base name if `field_name` carries a recognized
/// segment suffix (e.g. `"col__length"` → `Some("col")`). Returns `None`
/// when the name does not match any known segment suffix — that case can
/// either mean a primary segment (the column itself) or an unrelated name.
pub fn segment_base_name(field_name: &str) -> Option<&str> {
    if let Some(base) = field_name.strip_suffix(STRING_LENGTH_SUFFIX) {
        return Some(base);
    }
    if let Some(base) = field_name.strip_suffix(STRING_CHARS_SUFFIX) {
        return Some(base);
    }
    // Match `__enc<N>` auto-named segments.
    if let Some(enc_at) = field_name.rfind("__enc") {
        let rest = &field_name[enc_at + "__enc".len()..];
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return Some(&field_name[..enc_at]);
        }
    }
    None
}

/// True if `field_name` either equals `base_name` (the primary segment) or
/// is a recognized segment of `base_name` (e.g. `base_name__length`).
pub fn is_segment_of(field_name: &str, base_name: &str) -> bool {
    if field_name == base_name {
        return true;
    }
    matches!(segment_base_name(field_name), Some(base) if base == base_name)
}

/// Returns the ordered **row-domain** segment suffixes that
/// `encode_arrow_array_to_field` will produce for a column of the given Arrow
/// data type. Used by callers that have only the schema (no data) to
/// enumerate the same set of row-space segments the prover will produce —
/// e.g. the verifier-side tracking pass.
///
/// Side-domain segments (e.g. `__chars` for strings) are NOT included here;
/// see [`side_segment_suffixes_for_type`] to enumerate those separately.
///
/// Must stay in lockstep with the encoder implementations below.
pub fn segment_suffixes_for_type<F: PrimeField>(dtype: &DataType) -> Vec<String> {
    let auto = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| {
                if i == 0 {
                    String::new()
                } else {
                    format!("__enc{i}")
                }
            })
            .collect()
    };
    let hash_slots = 32usize.div_ceil(field_element_byte_capacity::<F>());

    match dtype {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => {
            let mut s = auto(hash_slots);
            s.push(STRING_LENGTH_SUFFIX.to_string());
            s
        }
        DataType::Binary
        | DataType::LargeBinary
        | DataType::BinaryView
        | DataType::FixedSizeBinary(_) => auto(hash_slots),
        DataType::Interval(IntervalUnit::DayTime) => {
            auto(8usize.div_ceil(field_element_byte_capacity::<F>()))
        }
        DataType::Interval(IntervalUnit::MonthDayNano) => {
            auto(16usize.div_ceil(field_element_byte_capacity::<F>()))
        }
        _ => vec![String::new()],
    }
}

/// Returns the **side-domain** segment suffixes the encoder will emit for the
/// given Arrow data type, in the same order the encoder produces them. The
/// verifier-side tracking pass uses this to enumerate the side commitments it
/// must consume from the proof transcript.
///
/// Each side segment carries its own (data, activator) commitment pair; the
/// per-segment `log_size` is shared via the transcript's miscellaneous fields
/// since it depends on prover-side data.
pub fn side_segment_suffixes_for_type<F: PrimeField>(dtype: &DataType) -> Vec<String> {
    match dtype {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => {
            vec![STRING_CHARS_SUFFIX.to_string()]
        }
        _ => Vec::new(),
    }
}

// Implementation of Encodable for various Arrow array types.
// Boolean
impl_col_adapter_map!(BooleanArray, |v| if v { F::one() } else { F::zero() });
// Integers
impl_col_adapter_map!(Int8Array, |v| F::from(v as i128));
impl_col_adapter_map!(Int16Array, |v| F::from(v as i128));
impl_col_adapter_map!(Int32Array, |v| F::from(v as i128));
impl_col_adapter_map!(Int64Array, |v| F::from(v as i128));
// Unsigned Integers
impl_col_adapter_map!(UInt8Array, |v| F::from(v as u64));
impl_col_adapter_map!(UInt16Array, |v| F::from(v as u64));
impl_col_adapter_map!(UInt32Array, |v| F::from(v as u64));
impl_col_adapter_map!(UInt64Array, |v| F::from(v));
// Floating point numbers
impl_col_adapter_map!(Float16Array, |v: <datafusion::arrow::datatypes::Float16Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_bits().to_le_bytes()
));
impl_col_adapter_map!(Float32Array, |v: <datafusion::arrow::datatypes::Float32Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));
impl_col_adapter_map!(Float64Array, |v: <datafusion::arrow::datatypes::Float64Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));
// TimeStamps
impl_col_adapter_map!(TimestampSecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampMillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampMicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampNanosecondArray, |v| F::from(v as i128));
// Date
impl_col_adapter_map!(Date32Array, |v| F::from(v));
impl_col_adapter_map!(Date64Array, |v| F::from(v));
// Time
impl_col_adapter_map!(Time32SecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time32MillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time64MicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time64NanosecondArray, |v| F::from(v as i128));
// Duration
impl_col_adapter_map!(DurationSecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationMillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationMicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationNanosecondArray, |v| F::from(v as i128));
//

impl_col_adapter_map!(IntervalYearMonthArray, |v| F::from(v as i128));

impl_col_adapter_map!(Decimal128Array, |v: <datafusion::arrow::datatypes::Decimal128Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));
impl_col_adapter_map!(Decimal256Array, |v: <datafusion::arrow::datatypes::Decimal256Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));

#[inline]
fn hash_to_32_bytes(data: &[u8]) -> [u8; 32] {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    fn fnv1a_with_seed(data: &[u8], seed: u64) -> u64 {
        let mut hash = seed;
        for &byte in data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    let mut out = [0u8; 32];
    let mut seed = FNV_OFFSET_BASIS;
    for i in 0..4 {
        let hash = fnv1a_with_seed(data, seed);
        out[i * 8..(i + 1) * 8].copy_from_slice(&hash.to_le_bytes());
        seed ^= hash.rotate_left(13);
    }
    out
}

#[inline]
fn encode_hashed_bytes<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    let hash_bytes = hash_to_32_bytes(bytes);
    encode_bytes_to_fields::<F>(&hash_bytes)
}

/// Encode an Arrow `ScalarValue` to its (one or more) row-domain field-element
/// segments. Each returned segment carries exactly one value (the scalar) plus
/// the suffix that downstream consumers should use to address it.
///
/// Side-domain segments (e.g. the per-column `__chars` poly produced for
/// strings) are intentionally dropped here: literals are constants that
/// broadcast across rows, so there is no meaningful concatenated-characters
/// polynomial to commit for them.
pub fn scalar_to_fields<F: PrimeField>(scalar: &ScalarValue) -> Option<Vec<EncodedSegment<F>>> {
    let array = scalar.to_array().ok()?;
    let segments = encode_arrow_array_to_field::<F>(&array).ok()?;
    let row_segments: Vec<EncodedSegment<F>> =
        segments.into_iter().filter(|s| !s.is_side()).collect();
    if row_segments.is_empty() {
        return None;
    }
    for segment in &row_segments {
        if segment.values.len() != 1 {
            return None;
        }
    }
    Some(row_segments)
}

/// Convenience for callers that only need the primary segment's single field
/// element. Returns `None` for scalars whose encoding expands into multiple
/// segments (e.g. strings, which produce `[hash, length]`).
pub fn scalar_to_field<F: PrimeField>(scalar: &ScalarValue) -> Option<F> {
    let segments = scalar_to_fields::<F>(scalar)?;
    if segments.len() != 1 {
        return None;
    }
    segments.into_iter().next()?.values.into_iter().next()
}

impl<F: PrimeField> Encodable<F> for BinaryArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let cols = collect_by_columns(self.len(), |idx| {
            if self.is_null(idx) {
                Vec::new()
            } else {
                encode_hashed_bytes::<F>(self.value(idx))
            }
        });
        Ok(auto_segments(cols))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(BinaryArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for LargeBinaryArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let cols = collect_by_columns(self.len(), |idx| {
            if self.is_null(idx) {
                Vec::new()
            } else {
                encode_hashed_bytes::<F>(self.value(idx))
            }
        });
        Ok(auto_segments(cols))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(LargeBinaryArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for BinaryViewArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let cols = collect_by_columns(self.len(), |idx| {
            if self.is_null(idx) {
                Vec::new()
            } else {
                encode_hashed_bytes::<F>(self.value(idx))
            }
        });
        Ok(auto_segments(cols))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(BinaryViewArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for FixedSizeBinaryArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let cols = collect_by_columns(self.len(), |idx| {
            if self.is_null(idx) {
                Vec::new()
            } else {
                encode_hashed_bytes::<F>(self.value(idx))
            }
        });
        Ok(auto_segments(cols))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(FixedSizeBinaryArray)
        );
    }
}

fn encode_utf8_like<F, A, GetValue>(
    array: &A,
    short_string_threshold: usize,
    value_fn: GetValue,
) -> Result<Vec<EncodedSegment<F>>, EncodeError>
where
    F: PrimeField,
    A: Array,
    GetValue: Copy + Fn(&A, usize) -> &str,
{
    let rows = array.len();
    let mut max_len = 0usize;
    for idx in 0..rows {
        if !array.is_null(idx) {
            let len = value_fn(array, idx).len();
            if len > max_len {
                max_len = len;
            }
        }
    }

    let inline_short = max_len <= short_string_threshold && max_len <= 1;
    // Fixed shape per column so all-null arrays still produce both segments
    // (hash slots + length). Hash slot count is constant for a given field:
    // hash_to_32_bytes always emits 32 bytes, chunked by field byte capacity.
    let hash_slots = if inline_short {
        1
    } else {
        32usize.div_ceil(field_element_byte_capacity::<F>())
    };

    let mut hash_cols: Vec<Vec<F>> = (0..hash_slots)
        .map(|_| Vec::with_capacity(rows))
        .collect();
    let mut length_col: Vec<F> = Vec::with_capacity(rows);
    // Characters side polynomial: concatenated bytes of all non-null strings
    // in row order. Null/inactive rows contribute zero bytes (their length is
    // already 0 in `length_col`), so the contiguous-one activator computed
    // below correctly marks "active byte" positions at the start of the
    // padded buffer.
    let total_chars: usize = (0..rows)
        .map(|idx| {
            if array.is_null(idx) {
                0
            } else {
                value_fn(array, idx).len()
            }
        })
        .sum();
    // Raw byte storage (one byte per slot) — kept as `Vec<u8>` so it stays
    // 32× smaller than the field-element form. Downstream commit / track
    // passes lift to `MLE<F>` only transiently.
    let mut chars_bytes: Vec<u8> = Vec::with_capacity(total_chars);

    for idx in 0..rows {
        if array.is_null(idx) {
            for col in &mut hash_cols {
                col.push(F::zero());
            }
            length_col.push(F::zero());
            continue;
        }
        let bytes = value_fn(array, idx).as_bytes();
        if inline_short {
            let head = if bytes.is_empty() {
                F::zero()
            } else {
                F::from(bytes[0] as u64)
            };
            hash_cols[0].push(head);
        } else {
            let chunks = encode_hashed_bytes::<F>(bytes);
            for (slot, col) in hash_cols.iter_mut().enumerate() {
                col.push(chunks.get(slot).copied().unwrap_or_else(F::zero));
            }
        }
        length_col.push(F::from(bytes.len() as u64));
        chars_bytes.extend_from_slice(bytes);
    }

    // Pad chars segment to a power-of-two length so it forms a valid MLE
    // domain. An empty column still produces a 1-slot, all-zero side poly so
    // downstream tracking sees a consistent shape.
    let chars_active_len = chars_bytes.len();
    let chars_target_len = chars_active_len.max(1).next_power_of_two();
    chars_bytes.resize(chars_target_len, 0u8);

    let mut segments = auto_segments(hash_cols);
    segments.push(EncodedSegment::named(STRING_LENGTH_SUFFIX, length_col));
    segments.push(EncodedSegment::side(
        STRING_CHARS_SUFFIX,
        chars_bytes,
        chars_active_len,
    ));
    Ok(segments)
}

impl<F: PrimeField> Encodable<F> for StringArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        encode_utf8_like::<F, _, _>(self, 32, |array, idx| array.value(idx))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(StringArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for LargeStringArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        encode_utf8_like::<F, _, _>(self, 32, |array, idx| array.value(idx))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(LargeStringArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for StringViewArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        encode_utf8_like::<F, _, _>(self, 32, |array, idx| array.value(idx))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(StringViewArray)
        );
    }
}

// Some manual implementation of Encodable for complex types

impl<F: PrimeField> Encodable<F> for NullArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        Ok(vec![EncodedSegment::primary(vec![F::zero(); self.len()])])
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding {} is not implemented yet", stringify!(NullArray));
    }
}

impl<F: PrimeField> Encodable<F> for IntervalDayTimeArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let cols = collect_by_columns(self.len(), |idx| {
            if self.is_null(idx) {
                Vec::new()
            } else {
                let interval = self.value(idx);
                let mut bytes = [0u8; 8];
                bytes[..4].copy_from_slice(&interval.days.to_le_bytes());
                bytes[4..].copy_from_slice(&interval.milliseconds.to_le_bytes());
                encode_bytes_to_fields::<F>(&bytes)
            }
        });
        Ok(auto_segments(cols))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(IntervalDayTimeArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for IntervalMonthDayNanoArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let cols = collect_by_columns(self.len(), |idx| {
            if self.is_null(idx) {
                Vec::new()
            } else {
                let interval = self.value(idx);
                let mut bytes = [0u8; 16];
                bytes[0..4].copy_from_slice(&interval.months.to_le_bytes());
                bytes[4..8].copy_from_slice(&interval.days.to_le_bytes());
                bytes[8..16].copy_from_slice(&interval.nanoseconds.to_le_bytes());
                encode_bytes_to_fields::<F>(&bytes)
            }
        });
        Ok(auto_segments(cols))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(IntervalMonthDayNanoArray)
        );
    }
}

impl<F: PrimeField, K> Encodable<F> for DictionaryArray<K>
where
    K: datafusion::arrow::datatypes::ArrowDictionaryKeyType,
{
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        Err(EncodeError::TypeNotSupported("Dictionary".to_string()))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(DictionaryArray<K>)
        );
    }
}

// Unsupported data types
impl_col_adapter_unsupported!(ListArray, "List");
impl_col_adapter_unsupported!(LargeListArray, "LargeList");
impl_col_adapter_unsupported!(ListViewArray, "ListView");
impl_col_adapter_unsupported!(LargeListViewArray, "LargeListView");
impl_col_adapter_unsupported!(FixedSizeListArray, "FixedSizeList");
impl_col_adapter_unsupported!(StructArray, "Struct");
impl_col_adapter_unsupported!(UnionArray, "Union");
impl_col_adapter_unsupported!(MapArray, "Map");
impl_col_adapter_unsupported!(Int16RunArray, "RunEndEncoded");
impl_col_adapter_unsupported!(Int32RunArray, "RunEndEncoded");
impl_col_adapter_unsupported!(Int64RunArray, "RunEndEncoded");

#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(
        len = array.len(),
        dtype = %array.data_type()
    )
)]
/// The main function for dispatching encoders based on the Arrow data type.
pub fn encode_arrow_array_to_field<F: PrimeField>(
    array: &ArrayRef,
) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
    fn downcast_and_encode<F: PrimeField, A: Encodable<F> + 'static>(
        array: &ArrayRef,
        err_msg: &'static str,
    ) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        array.as_any().downcast_ref::<A>().expect(err_msg).encode()
    }

    match array.data_type() {
        DataType::Null => {
            downcast_and_encode::<F, NullArray>(array, "array downcast to NullArray failed")
        }
        DataType::Boolean => {
            downcast_and_encode::<F, BooleanArray>(array, "array downcast to BooleanArray failed")
        }
        DataType::Int8 => {
            downcast_and_encode::<F, Int8Array>(array, "array downcast to Int8Array failed")
        }
        DataType::Int16 => {
            downcast_and_encode::<F, Int16Array>(array, "array downcast to Int16Array failed")
        }
        DataType::Int32 => {
            downcast_and_encode::<F, Int32Array>(array, "array downcast to Int32Array failed")
        }
        DataType::Int64 => {
            downcast_and_encode::<F, Int64Array>(array, "array downcast to Int64Array failed")
        }
        DataType::UInt8 => {
            downcast_and_encode::<F, UInt8Array>(array, "array downcast to UInt8Array failed")
        }
        DataType::UInt16 => {
            downcast_and_encode::<F, UInt16Array>(array, "array downcast to UInt16Array failed")
        }
        DataType::UInt32 => {
            downcast_and_encode::<F, UInt32Array>(array, "array downcast to UInt32Array failed")
        }
        DataType::UInt64 => {
            downcast_and_encode::<F, UInt64Array>(array, "array downcast to UInt64Array failed")
        }
        DataType::Float16 => {
            downcast_and_encode::<F, Float16Array>(array, "array downcast to Float16Array failed")
        }
        DataType::Float32 => {
            downcast_and_encode::<F, Float32Array>(array, "array downcast to Float32Array failed")
        }
        DataType::Float64 => {
            downcast_and_encode::<F, Float64Array>(array, "array downcast to Float64Array failed")
        }
        DataType::Timestamp(unit, _) => match unit {
            TimeUnit::Second => downcast_and_encode::<F, TimestampSecondArray>(
                array,
                "array downcast to TimestampSecondArray failed",
            ),
            TimeUnit::Millisecond => downcast_and_encode::<F, TimestampMillisecondArray>(
                array,
                "array downcast to TimestampMillisecondArray failed",
            ),
            TimeUnit::Microsecond => downcast_and_encode::<F, TimestampMicrosecondArray>(
                array,
                "array downcast to TimestampMicrosecondArray failed",
            ),
            TimeUnit::Nanosecond => downcast_and_encode::<F, TimestampNanosecondArray>(
                array,
                "array downcast to TimestampNanosecondArray failed",
            ),
        },
        DataType::Date32 => {
            downcast_and_encode::<F, Date32Array>(array, "array downcast to Date32Array failed")
        }
        DataType::Date64 => {
            downcast_and_encode::<F, Date64Array>(array, "array downcast to Date64Array failed")
        }
        DataType::Time32(unit) => match unit {
            TimeUnit::Second => downcast_and_encode::<F, Time32SecondArray>(
                array,
                "array downcast to Time32SecondArray failed",
            ),
            TimeUnit::Millisecond => downcast_and_encode::<F, Time32MillisecondArray>(
                array,
                "array downcast to Time32MillisecondArray failed",
            ),
            _ => Err(EncodeError::TypeNotSupported(format!(
                "Time32 unit {unit:?} is not supported"
            ))),
        },
        DataType::Time64(unit) => match unit {
            TimeUnit::Microsecond => downcast_and_encode::<F, Time64MicrosecondArray>(
                array,
                "array downcast to Time64MicrosecondArray failed",
            ),
            TimeUnit::Nanosecond => downcast_and_encode::<F, Time64NanosecondArray>(
                array,
                "array downcast to Time64NanosecondArray failed",
            ),
            _ => Err(EncodeError::TypeNotSupported(format!(
                "Time64 unit {unit:?} is not supported"
            ))),
        },
        DataType::Duration(unit) => match unit {
            TimeUnit::Second => downcast_and_encode::<F, DurationSecondArray>(
                array,
                "array downcast to DurationSecondArray failed",
            ),
            TimeUnit::Millisecond => downcast_and_encode::<F, DurationMillisecondArray>(
                array,
                "array downcast to DurationMillisecondArray failed",
            ),
            TimeUnit::Microsecond => downcast_and_encode::<F, DurationMicrosecondArray>(
                array,
                "array downcast to DurationMicrosecondArray failed",
            ),
            TimeUnit::Nanosecond => downcast_and_encode::<F, DurationNanosecondArray>(
                array,
                "array downcast to DurationNanosecondArray failed",
            ),
        },
        DataType::Interval(unit) => match unit {
            IntervalUnit::YearMonth => downcast_and_encode::<F, IntervalYearMonthArray>(
                array,
                "array downcast to IntervalYearMonthArray failed",
            ),
            IntervalUnit::DayTime => downcast_and_encode::<F, IntervalDayTimeArray>(
                array,
                "array downcast to IntervalDayTimeArray failed",
            ),
            IntervalUnit::MonthDayNano => downcast_and_encode::<F, IntervalMonthDayNanoArray>(
                array,
                "array downcast to IntervalMonthDayNanoArray failed",
            ),
        },
        DataType::Binary => {
            downcast_and_encode::<F, BinaryArray>(array, "array downcast to BinaryArray failed")
        }
        DataType::LargeBinary => downcast_and_encode::<F, LargeBinaryArray>(
            array,
            "array downcast to LargeBinaryArray failed",
        ),
        DataType::BinaryView => downcast_and_encode::<F, BinaryViewArray>(
            array,
            "array downcast to BinaryViewArray failed",
        ),
        DataType::FixedSizeBinary(_) => downcast_and_encode::<F, FixedSizeBinaryArray>(
            array,
            "array downcast to FixedSizeBinaryArray failed",
        ),
        DataType::Utf8 => {
            downcast_and_encode::<F, StringArray>(array, "array downcast to StringArray failed")
        }
        DataType::LargeUtf8 => downcast_and_encode::<F, LargeStringArray>(
            array,
            "array downcast to LargeStringArray failed",
        ),
        DataType::Utf8View => downcast_and_encode::<F, StringViewArray>(
            array,
            "array downcast to StringViewArray failed",
        ),
        DataType::List(_) => {
            downcast_and_encode::<F, ListArray>(array, "array downcast to ListArray failed")
        }
        DataType::LargeList(_) => downcast_and_encode::<F, LargeListArray>(
            array,
            "array downcast to LargeListArray failed",
        ),
        DataType::ListView(_) => {
            downcast_and_encode::<F, ListViewArray>(array, "array downcast to ListViewArray failed")
        }
        DataType::LargeListView(_) => downcast_and_encode::<F, LargeListViewArray>(
            array,
            "array downcast to LargeListViewArray failed",
        ),
        DataType::FixedSizeList(..) => downcast_and_encode::<F, FixedSizeListArray>(
            array,
            "array downcast to FixedSizeListArray failed",
        ),
        DataType::Struct(_) => {
            downcast_and_encode::<F, StructArray>(array, "array downcast to StructArray failed")
        }
        DataType::Union(..) => {
            downcast_and_encode::<F, UnionArray>(array, "array downcast to UnionArray failed")
        }
        DataType::Dictionary(key_type, _) => match key_type.as_ref() {
            DataType::Int8 => downcast_and_encode::<F, Int8DictionaryArray>(
                array,
                "array downcast to Int8DictionaryArray failed",
            ),
            DataType::Int16 => downcast_and_encode::<F, Int16DictionaryArray>(
                array,
                "array downcast to Int16DictionaryArray failed",
            ),
            DataType::Int32 => downcast_and_encode::<F, Int32DictionaryArray>(
                array,
                "array downcast to Int32DictionaryArray failed",
            ),
            DataType::Int64 => downcast_and_encode::<F, Int64DictionaryArray>(
                array,
                "array downcast to Int64DictionaryArray failed",
            ),
            DataType::UInt8 => downcast_and_encode::<F, UInt8DictionaryArray>(
                array,
                "array downcast to UInt8DictionaryArray failed",
            ),
            DataType::UInt16 => downcast_and_encode::<F, UInt16DictionaryArray>(
                array,
                "array downcast to UInt16DictionaryArray failed",
            ),
            DataType::UInt32 => downcast_and_encode::<F, UInt32DictionaryArray>(
                array,
                "array downcast to UInt32DictionaryArray failed",
            ),
            DataType::UInt64 => downcast_and_encode::<F, UInt64DictionaryArray>(
                array,
                "array downcast to UInt64DictionaryArray failed",
            ),
            other => Err(EncodeError::TypeNotSupported(format!(
                "Dictionary key type {other} is not supported"
            ))),
        },
        DataType::Map(..) => {
            downcast_and_encode::<F, MapArray>(array, "array downcast to MapArray failed")
        }
        DataType::Decimal128(..) => downcast_and_encode::<F, Decimal128Array>(
            array,
            "array downcast to Decimal128Array failed",
        ),
        DataType::Decimal256(..) => downcast_and_encode::<F, Decimal256Array>(
            array,
            "array downcast to Decimal256Array failed",
        ),
        DataType::RunEndEncoded(run_ends, _) => match run_ends.data_type() {
            DataType::Int16 => downcast_and_encode::<F, Int16RunArray>(
                array,
                "array downcast to Int16RunArray failed",
            ),
            DataType::Int32 => downcast_and_encode::<F, Int32RunArray>(
                array,
                "array downcast to Int32RunArray failed",
            ),
            DataType::Int64 => downcast_and_encode::<F, Int64RunArray>(
                array,
                "array downcast to Int64RunArray failed",
            ),
            other => Err(EncodeError::TypeNotSupported(format!(
                "Run-end index type {other} is not supported"
            ))),
        },
    }
}

fn field_element_byte_capacity<F: PrimeField>() -> usize {
    let bits = F::MODULUS_BIT_SIZE as usize;
    let bytes = bits.div_ceil(8);
    bytes.max(1)
}

fn encode_bytes_to_fields<F: PrimeField>(bytes: &[u8]) -> Vec<F> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let chunk_size = field_element_byte_capacity::<F>();
    bytes
        .chunks(chunk_size)
        .map(|chunk| F::from_le_bytes_mod_order(chunk))
        .collect()
}

fn collect_by_columns<F: PrimeField, R>(rows: usize, mut row_fn: R) -> Vec<Vec<F>>
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use ark_test_curves::bls12_381::Fr;
    use datafusion::arrow::array::StringArray;

    #[test]
    fn single_character_strings_are_inlined() {
        let array = StringArray::from(vec![Some("a"), Some(""), None, Some("Z")]);
        let encoded = <StringArray as Encodable<Fr>>::encode(&array).unwrap();

        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0].suffix, "");
        assert_eq!(encoded[1].suffix, STRING_LENGTH_SUFFIX);
        let hash_col = &encoded[0].values;
        let length_col = &encoded[1].values;
        assert_eq!(hash_col.len(), array.len());
        assert_eq!(length_col.len(), array.len());
        assert_eq!(hash_col[0], Fr::from(97u64));
        assert_eq!(hash_col[1], Fr::zero());
        assert_eq!(hash_col[2], Fr::zero());
        assert_eq!(hash_col[3], Fr::from(90u64));
        assert_eq!(length_col[0], Fr::from(1u64));
        assert_eq!(length_col[1], Fr::zero());
        assert_eq!(length_col[2], Fr::zero());
        assert_eq!(length_col[3], Fr::from(1u64));
    }

    #[test]
    fn multi_character_strings_are_hashed() {
        let array = StringArray::from(vec![Some("foo"), Some("bar"), None, Some("baz")]);
        let encoded = <StringArray as Encodable<Fr>>::encode(&array).unwrap();

        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded[0].suffix, "");
        assert_eq!(encoded[1].suffix, STRING_LENGTH_SUFFIX);
        let hash_col = &encoded[0].values;
        let length_col = &encoded[1].values;
        assert_eq!(hash_col.len(), array.len());
        assert_eq!(length_col.len(), array.len());
        assert_eq!(hash_col[0], encode_hashed_bytes::<Fr>(b"foo")[0]);
        assert_eq!(hash_col[1], encode_hashed_bytes::<Fr>(b"bar")[0]);
        assert_eq!(hash_col[2], Fr::zero());
        assert_eq!(hash_col[3], encode_hashed_bytes::<Fr>(b"baz")[0]);
        assert_eq!(length_col[0], Fr::from(3u64));
        assert_eq!(length_col[1], Fr::from(3u64));
        assert_eq!(length_col[2], Fr::zero());
        assert_eq!(length_col[3], Fr::from(3u64));
    }

    #[test]
    fn string_scalar_encodes_to_multiple_segments() {
        let scalar = ScalarValue::Utf8(Some("hello".to_string()));
        let segments = scalar_to_fields::<Fr>(&scalar).expect("scalar should encode");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].suffix, "");
        assert_eq!(segments[1].suffix, STRING_LENGTH_SUFFIX);
        assert_eq!(segments[1].values, vec![Fr::from(5u64)]);
        // scalar_to_field's single-field convenience refuses multi-segment scalars
        assert!(scalar_to_field::<Fr>(&scalar).is_none());
    }

    // #[test]
    // fn large_string_array_follows_same_rules() {
    //     let array = LargeStringArray::from(vec![Some("x"), Some("yz"),
    // None]);     let encoded = <LargeStringArray as
    // Encodable<Fr>>::encode(&array).unwrap();

    //     assert_eq!(encoded.len(), 1);
    //     let column = &encoded[0];
    //     assert_eq!(column[0], Fr::from(120u64));
    //     assert_eq!(column[1], encode_hashed_bytes::<Fr>(b"yz")[0]);
    //     assert_eq!(column[2], Fr::zero());
    // }

    // #[test]
    // fn string_view_array_matches_behavior() {
    //     let array = StringViewArray::from(vec![Some("m"), Some("no"), None]);
    //     let encoded = <StringViewArray as
    // Encodable<Fr>>::encode(&array).unwrap();

    //     assert_eq!(encoded.len(), 1);
    //     let column = &encoded[0];
    //     assert_eq!(column[0], Fr::from(109u64));
    //     assert_eq!(column[1], encode_hashed_bytes::<Fr>(b"no")[0]);
    //     assert_eq!(column[2], Fr::zero());
    // }
}
