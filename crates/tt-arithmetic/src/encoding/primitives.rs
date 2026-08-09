//! Encoders for scalar-shaped Arrow arrays.
//!
//! Each `impl Encodable` here picks the smallest [`MLEStorage`] variant that
//! faithfully represents the column, so the resulting `MLE` is built directly
//! as `MLE::Bit`, `MLE::U8`, `MLE::U32`, or `MLE::U64` storage — no `Vec<F>`
//! materialization at any point in the row-domain ingest path.
//!
//! Signed integer types (`Int8Array`, …, `Int64Array`) peek at their values
//! first: if every entry is `>= 0` they use the matching unsigned variant
//! (`from_u8s` / `from_u32s` / `from_u64s`); otherwise they fall back to a
//! field-element MLE because a negative in `F` is `MODULUS - abs(v)`, a
//! full-fat 254-bit scalar that no compressed variant can hold. Nulls read
//! as zero (matches the eager-encoding contract).
//!
//! Decimals stay field-native — `from_le_bytes_mod_order` is intrinsically
//! field-native. Same for `Interval*` limb packings in `other.rs`.

use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::array::{
    Array, BooleanArray, Date32Array, Date64Array, Decimal128Array, Decimal256Array,
    DurationMicrosecondArray, DurationMillisecondArray, DurationNanosecondArray,
    DurationSecondArray, Int8Array, Int16Array, Int32Array, Int64Array, IntervalYearMonthArray,
    Time32MillisecondArray, Time32SecondArray, Time64MicrosecondArray, Time64NanosecondArray,
    TimestampMicrosecondArray, TimestampMillisecondArray, TimestampNanosecondArray,
    TimestampSecondArray, UInt8Array, UInt16Array, UInt32Array, UInt64Array,
};

use crate::errors::EncodeError;

use super::encodable::{impl_col_adapter_map, Encodable};
use super::segment::{auto_segments, EncodedSegment};
use super::util::collect_by_columns;

/// Number of multilinear variables corresponding to a physical `len`.
/// Encoders always receive pow2-length arrays in our pipeline (arithmetization
/// pow2-asserts row batches; scalars are len=1; string encoder pow2-pads side
/// buffers), so the ilog2 is exact.
#[inline]
fn num_vars_of(len: usize) -> usize {
    assert!(
        len.is_power_of_two(),
        "encoder received non-power-of-two array length {len}"
    );
    len.trailing_zeros() as usize
}

// ── Boolean ──────────────────────────────────────────────────────────────
//
// Bit-packed MLE. Semantics preserved from the previous `if v { F::one() }
// else { F::zero() }` mapping: nulls read as `false` → `F::zero()`, matching
// the eager encoder's null contract.

impl<F: PrimeField> Encodable<F> for BooleanArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let len = self.len();
        let byte_len = len.div_ceil(8).max(1);
        let mut bits = vec![0u8; byte_len];
        for i in 0..len {
            if !self.is_null(i) && self.value(i) {
                bits[i >> 3] |= 1u8 << (i & 7);
            }
        }
        let mle = MLE::<F>::from_bit_backing(bits, num_vars_of(len));
        Ok(vec![EncodedSegment::primary_mle(mle)])
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding BooleanArray is not implemented yet")
    }
}

// ── Unsigned integers ────────────────────────────────────────────────────
//
// Direct handoff of the arrow buffer into the matching MLE variant. Nulls
// read as 0 (matches the previous `F::zero()` contract).

impl<F: PrimeField> Encodable<F> for UInt8Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let bytes: Vec<u8> = (0..self.len())
            .map(|i| if self.is_null(i) { 0 } else { self.value(i) })
            .collect();
        let mle = MLE::<F>::from_u8s(bytes, num_vars_of(self.len()));
        Ok(vec![EncodedSegment::primary_mle(mle)])
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding UInt8Array is not implemented yet")
    }
}

impl<F: PrimeField> Encodable<F> for UInt16Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        // Promote u16 → u32 at MLE-construction time. `MLEStorage` has no
        // `U16` variant; the 2× hit is still 8× smaller than Field storage
        // and lets us reuse the existing U32 commit / lift paths.
        let words: Vec<u32> = (0..self.len())
            .map(|i| if self.is_null(i) { 0 } else { self.value(i) as u32 })
            .collect();
        let mle = MLE::<F>::from_u32s(words, num_vars_of(self.len()));
        Ok(vec![EncodedSegment::primary_mle(mle)])
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding UInt16Array is not implemented yet")
    }
}

impl<F: PrimeField> Encodable<F> for UInt32Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let words: Vec<u32> = (0..self.len())
            .map(|i| if self.is_null(i) { 0 } else { self.value(i) })
            .collect();
        let mle = MLE::<F>::from_u32s(words, num_vars_of(self.len()));
        Ok(vec![EncodedSegment::primary_mle(mle)])
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding UInt32Array is not implemented yet")
    }
}

impl<F: PrimeField> Encodable<F> for UInt64Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let words: Vec<u64> = (0..self.len())
            .map(|i| if self.is_null(i) { 0 } else { self.value(i) })
            .collect();
        let mle = MLE::<F>::from_u64s(words, num_vars_of(self.len()));
        Ok(vec![EncodedSegment::primary_mle(mle)])
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding UInt64Array is not implemented yet")
    }
}

// ── Signed integers (sign-peek → unsigned MLE, else Fs fallback) ─────
//
// A signed value `v < 0` maps to `F::from(v as i128)` which internally
// becomes `MODULUS - abs(v)` — a full 254-bit scalar with no small-int
// representation. So we scan once: if every non-null entry is non-negative
// we use the matching unsigned MLE (`v as uN`); if any entry is negative we
// fall back to a full-fat Field MLE, matching the previous behavior
// bit-for-bit.
//
// Nulls read as zero (matches the previous `F::zero()` null semantics),
// same as the unsigned encoders above.

// Sign-peek inlined per encoder rather than lifted to a generic — the arrow
// `ArrayAccessor` trait is implemented on `&PrimitiveArray<T>`, not the owned
// type, and the resulting bound leaks lifetime noise into every call site.
// The one-liner `(0..len).all(|i| self.is_null(i) || self.value(i) >= 0)` is
// clearer and monomorphizes cleanly per type.

impl<F: PrimeField> Encodable<F> for Int8Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let bytes: Vec<u8> = (0..self.len())
                .map(|i| if self.is_null(i) { 0 } else { self.value(i) as u8 })
                .collect();
            let mle = MLE::<F>::from_u8s(bytes, num_vars_of(self.len()));
            return Ok(vec![EncodedSegment::primary_mle(mle)]);
        }
        // Fallback: field-native encoding (matches prior semantics).
        let cols = collect_by_columns(self.len(), |i| {
            if self.is_null(i) {
                vec![F::zero()]
            } else {
                vec![F::from(self.value(i) as i128)]
            }
        });
        Ok(auto_segments(cols))
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding Int8Array is not implemented yet")
    }
}

impl<F: PrimeField> Encodable<F> for Int16Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            // Same u16 → u32 promotion as UInt16Array above.
            let words: Vec<u32> = (0..self.len())
                .map(|i| if self.is_null(i) { 0 } else { self.value(i) as u32 })
                .collect();
            let mle = MLE::<F>::from_u32s(words, num_vars_of(self.len()));
            return Ok(vec![EncodedSegment::primary_mle(mle)]);
        }
        let cols = collect_by_columns(self.len(), |i| {
            if self.is_null(i) {
                vec![F::zero()]
            } else {
                vec![F::from(self.value(i) as i128)]
            }
        });
        Ok(auto_segments(cols))
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding Int16Array is not implemented yet")
    }
}

impl<F: PrimeField> Encodable<F> for Int32Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let words: Vec<u32> = (0..self.len())
                .map(|i| if self.is_null(i) { 0 } else { self.value(i) as u32 })
                .collect();
            let mle = MLE::<F>::from_u32s(words, num_vars_of(self.len()));
            return Ok(vec![EncodedSegment::primary_mle(mle)]);
        }
        let cols = collect_by_columns(self.len(), |i| {
            if self.is_null(i) {
                vec![F::zero()]
            } else {
                vec![F::from(self.value(i) as i128)]
            }
        });
        Ok(auto_segments(cols))
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding Int32Array is not implemented yet")
    }
}

impl<F: PrimeField> Encodable<F> for Int64Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let words: Vec<u64> = (0..self.len())
                .map(|i| if self.is_null(i) { 0 } else { self.value(i) as u64 })
                .collect();
            let mle = MLE::<F>::from_u64s(words, num_vars_of(self.len()));
            return Ok(vec![EncodedSegment::primary_mle(mle)]);
        }
        let cols = collect_by_columns(self.len(), |i| {
            if self.is_null(i) {
                vec![F::zero()]
            } else {
                vec![F::from(self.value(i) as i128)]
            }
        });
        Ok(auto_segments(cols))
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding Int64Array is not implemented yet")
    }
}

// ── Dates / times / timestamps / durations ───────────────────────────────
//
// Arrow stores these as signed integers of various widths. The same
// sign-peek rule applies — non-negative → matching unsigned MLE, negative →
// field fallback.

impl<F: PrimeField> Encodable<F> for Date32Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        // Date32 is days-since-epoch as i32. Realistic date columns are
        // post-1970 → non-negative → U32.
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let words: Vec<u32> = (0..self.len())
                .map(|i| if self.is_null(i) { 0 } else { self.value(i) as u32 })
                .collect();
            let mle = MLE::<F>::from_u32s(words, num_vars_of(self.len()));
            return Ok(vec![EncodedSegment::primary_mle(mle)]);
        }
        let cols = collect_by_columns(self.len(), |i| {
            if self.is_null(i) {
                vec![F::zero()]
            } else {
                vec![F::from(self.value(i))]
            }
        });
        Ok(auto_segments(cols))
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding Date32Array is not implemented yet")
    }
}

impl<F: PrimeField> Encodable<F> for Date64Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        // Date64 is milliseconds-since-epoch as i64. Same rule as Date32.
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let words: Vec<u64> = (0..self.len())
                .map(|i| if self.is_null(i) { 0 } else { self.value(i) as u64 })
                .collect();
            let mle = MLE::<F>::from_u64s(words, num_vars_of(self.len()));
            return Ok(vec![EncodedSegment::primary_mle(mle)]);
        }
        let cols = collect_by_columns(self.len(), |i| {
            if self.is_null(i) {
                vec![F::zero()]
            } else {
                vec![F::from(self.value(i))]
            }
        });
        Ok(auto_segments(cols))
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding Date64Array is not implemented yet")
    }
}

// Time / Timestamp / Duration: kept on the eager Fs path for now. These
// types come up rarely in TPC-H and the value ranges vary widely by unit
// (seconds vs nanoseconds). Left as `impl_col_adapter_map!` so we preserve
// the pre-refactor behavior exactly for them; can be tightened later if a
// workload actually needs it.
impl_col_adapter_map!(TimestampSecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampMillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampMicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampNanosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time32SecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time32MillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time64MicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time64NanosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationSecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationMillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationMicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationNanosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(IntervalYearMonthArray, |v| F::from(v as i128));

// Decimals: intrinsically field-native (mod-order reduction), so field MLE.
impl_col_adapter_map!(Decimal128Array, |v: <datafusion::arrow::datatypes::Decimal128Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));
impl_col_adapter_map!(Decimal256Array, |v: <datafusion::arrow::datatypes::Decimal256Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));
