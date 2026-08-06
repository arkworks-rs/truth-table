use ark_ff::PrimeField;
use datafusion::arrow::array::{
    Array, BinaryArray, BinaryViewArray, DictionaryArray, FixedSizeBinaryArray,
    FixedSizeListArray, Float16Array, Float32Array, Float64Array, Int16RunArray, Int32RunArray,
    Int64RunArray, IntervalDayTimeArray, IntervalMonthDayNanoArray, LargeBinaryArray,
    LargeListArray, LargeListViewArray, ListArray, ListViewArray, MapArray, NullArray,
    StructArray, UnionArray,
};

use crate::errors::EncodeError;

use super::encodable::{impl_col_adapter_unsupported, Encodable};
use super::segment::{auto_segments, EncodedBacking, EncodedSegment};
use super::util::{collect_by_columns, encode_bytes_to_fields, encode_hashed_bytes};

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

// Some manual implementation of Encodable for complex types

impl<F: PrimeField> Encodable<F> for NullArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        // NullArray is all-zeros in F. The cheapest possible backing is
        // packed bits with every bit clear: `len.div_ceil(8)` bytes total,
        // 256× smaller than the prior `vec![F::zero(); len]` (which was
        // 32 B per zero). `MLEStorage::Bit` lifts an unset bit to
        // `F::zero()`, so semantics stay identical.
        let len = self.len();
        let byte_len = len.div_ceil(8).max(1);
        Ok(vec![EncodedSegment::primary_backed(EncodedBacking::Bits {
            bits: vec![0u8; byte_len],
            len,
        })])
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
// Floats: IEEE bit-cast into a prime field is not arithmetic-meaningful, so
// we reject them explicitly rather than silently pass through nonsense.
// Callers that need numeric semantics should convert to Decimal128 first
// (see `tt-tpch-data::convert_batch_to_decimalized`).
impl_col_adapter_unsupported!(Float16Array, "Float16");
impl_col_adapter_unsupported!(Float32Array, "Float32");
impl_col_adapter_unsupported!(Float64Array, "Float64");
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
