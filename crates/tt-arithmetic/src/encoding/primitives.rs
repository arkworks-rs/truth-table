//! Encoders for scalar-shaped Arrow arrays.
//!
//! Each encoder builds its `MLE` directly in the smallest storage that
//! represents the column (bits, `u8`, `u32`, `u64`, packed decimal), with
//! no intermediate `Vec<F>`. Nulls encode as zero.
//!
//! Signed types (integers, dates, `Decimal128`) use the unsigned storage
//! when every value is non-negative. Otherwise they fall back to field
//! elements: a negative `v` is `MODULUS - |v|` in `F`, which no compact
//! storage holds.

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

use super::encodable::{Encodable, impl_col_adapter_map};
use super::segment::{EncodedSegment, auto_segments};
use super::util::collect_by_columns;

/// Number of variables of an array of `len` rows. Arithmetization only
/// passes power-of-two row batches, and a scalar has one row.
#[inline]
fn num_vars_of(len: usize) -> usize {
    assert!(
        len.is_power_of_two(),
        "encoder received non-power-of-two array length {len}"
    );
    len.trailing_zeros() as usize
}

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
        // `MLEStorage` has no `U16` variant, so `u16` is stored as `u32`.
        let words: Vec<u32> = (0..self.len())
            .map(|i| {
                if self.is_null(i) {
                    0
                } else {
                    self.value(i) as u32
                }
            })
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

// The sign check is repeated per signed encoder instead of being generic:
// arrow implements `ArrayAccessor` on `&PrimitiveArray<T>`, not the owned
// type, and that bound would put a lifetime on every call site.

impl<F: PrimeField> Encodable<F> for Int8Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let bytes: Vec<u8> = (0..self.len())
                .map(|i| {
                    if self.is_null(i) {
                        0
                    } else {
                        self.value(i) as u8
                    }
                })
                .collect();
            let mle = MLE::<F>::from_u8s(bytes, num_vars_of(self.len()));
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
        todo!("Decoding Int8Array is not implemented yet")
    }
}

impl<F: PrimeField> Encodable<F> for Int16Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let words: Vec<u32> = (0..self.len())
                .map(|i| {
                    if self.is_null(i) {
                        0
                    } else {
                        self.value(i) as u32
                    }
                })
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
                .map(|i| {
                    if self.is_null(i) {
                        0
                    } else {
                        self.value(i) as u32
                    }
                })
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
                .map(|i| {
                    if self.is_null(i) {
                        0
                    } else {
                        self.value(i) as u64
                    }
                })
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

impl<F: PrimeField> Encodable<F> for Date32Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        // Days since the epoch as `i32`: non-negative from 1970 on.
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let words: Vec<u32> = (0..self.len())
                .map(|i| {
                    if self.is_null(i) {
                        0
                    } else {
                        self.value(i) as u32
                    }
                })
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
        // Milliseconds since the epoch as `i64`.
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let words: Vec<u64> = (0..self.len())
                .map(|i| {
                    if self.is_null(i) {
                        0
                    } else {
                        self.value(i) as u64
                    }
                })
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

// Times, timestamps, durations and year-month intervals are always encoded
// as field elements.
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

// A non-negative `Decimal128` column is stored packed, as high and low
// `u64` halves (16 bytes per row). A column with a negative value falls
// back to field elements through `from_le_bytes_mod_order`.
impl<F: PrimeField> Encodable<F> for Decimal128Array {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let all_non_negative = (0..self.len()).all(|i| self.is_null(i) || self.value(i) >= 0);
        if all_non_negative {
            let n = self.len();
            let mut high: Vec<u64> = Vec::with_capacity(n);
            let mut low: Vec<u64> = Vec::with_capacity(n);
            for i in 0..n {
                let v: u128 = if self.is_null(i) {
                    0
                } else {
                    self.value(i) as u128
                };
                high.push((v >> 64) as u64);
                low.push(v as u64);
            }
            // The fixed-point exponent of the data type. A `Decimal128`
            // scale is at most 38, so it fits a `u8`.
            let scale_u8 = self.scale() as u8;
            let mle = MLE::<F>::from_packed_decimal(high, low, scale_u8, num_vars_of(n));
            return Ok(vec![EncodedSegment::primary_mle(mle)]);
        }
        let cols = collect_by_columns(self.len(), |i| {
            if self.is_null(i) {
                vec![F::zero()]
            } else {
                vec![F::from_le_bytes_mod_order(&self.value(i).to_le_bytes())]
            }
        });
        Ok(auto_segments(cols))
    }
    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding Decimal128Array is not implemented yet")
    }
}
// `Decimal256` does not fit the packed storage.
impl_col_adapter_map!(Decimal256Array, |v: <datafusion::arrow::datatypes::Decimal256Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));
