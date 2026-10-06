use ark_ff::PrimeField;
use datafusion::arrow::array::{
    Array, ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Date64Array,
    Decimal128Array, Decimal256Array, DurationMicrosecondArray, DurationMillisecondArray,
    DurationNanosecondArray, DurationSecondArray, FixedSizeBinaryArray, FixedSizeListArray,
    Float16Array, Float32Array, Float64Array, Int8Array, Int8DictionaryArray, Int16Array,
    Int16DictionaryArray, Int16RunArray, Int32Array, Int32DictionaryArray, Int32RunArray,
    Int64Array, Int64DictionaryArray, Int64RunArray, IntervalDayTimeArray,
    IntervalMonthDayNanoArray, IntervalYearMonthArray, LargeBinaryArray, LargeListArray,
    LargeListViewArray, LargeStringArray, ListArray, ListViewArray, MapArray, NullArray,
    StringArray, StringViewArray, StructArray, Time32MillisecondArray, Time32SecondArray,
    Time64MicrosecondArray, Time64NanosecondArray, TimestampMicrosecondArray,
    TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt8Array,
    UInt8DictionaryArray, UInt16Array, UInt16DictionaryArray, UInt32Array, UInt32DictionaryArray,
    UInt64Array, UInt64DictionaryArray, UnionArray,
};
use datafusion::arrow::datatypes::{DataType, IntervalUnit, TimeUnit};
use datafusion_common::ScalarValue;

use crate::errors::EncodeError;

use super::encodable::{Encodable, EncodeOptions};
use super::segment::EncodedSegment;

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
    let segments =
        encode_arrow_array_to_field_with_options::<F>(&array, EncodeOptions::NONE).ok()?;
    let row_segments: Vec<EncodedSegment<F>> =
        segments.into_iter().filter(|s| !s.is_side()).collect();
    if row_segments.is_empty() {
        return None;
    }
    for segment in &row_segments {
        if segment.len() != 1 {
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
    let seg = segments.into_iter().next()?;
    (seg.len() == 1).then(|| seg.value_as_field(0))
}

#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(
        len = array.len(),
        dtype = %array.data_type()
    )
)]
/// The main function for dispatching encoders based on the Arrow data type.
/// Every optional segment is emitted; use
/// [`encode_arrow_array_to_field_with_options`] to suppress them at the source.
pub fn encode_arrow_array_to_field<F: PrimeField>(
    array: &ArrayRef,
) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
    encode_arrow_array_to_field_with_options(array, EncodeOptions::ALL)
}

/// Like [`encode_arrow_array_to_field`], but `options` can stop string
/// encoders from even *building* their char-level side buffers or fingerprint
/// limbs — callers that do not consume them (literals, intermediate
/// operators, columns without a pre-filter) skip that work instead of
/// dropping the segments later.
pub fn encode_arrow_array_to_field_with_options<F: PrimeField>(
    array: &ArrayRef,
    options: EncodeOptions<'_>,
) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
    fn downcast_and_encode<F: PrimeField, A: Encodable<F> + 'static>(
        array: &ArrayRef,
        options: EncodeOptions<'_>,
        err_msg: &'static str,
    ) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        array
            .as_any()
            .downcast_ref::<A>()
            .expect(err_msg)
            .encode_with_options(options)
    }

    match array.data_type() {
        DataType::Null => downcast_and_encode::<F, NullArray>(
            array,
            options,
            "array downcast to NullArray failed",
        ),
        DataType::Boolean => downcast_and_encode::<F, BooleanArray>(
            array,
            options,
            "array downcast to BooleanArray failed",
        ),
        DataType::Int8 => downcast_and_encode::<F, Int8Array>(
            array,
            options,
            "array downcast to Int8Array failed",
        ),
        DataType::Int16 => downcast_and_encode::<F, Int16Array>(
            array,
            options,
            "array downcast to Int16Array failed",
        ),
        DataType::Int32 => downcast_and_encode::<F, Int32Array>(
            array,
            options,
            "array downcast to Int32Array failed",
        ),
        DataType::Int64 => downcast_and_encode::<F, Int64Array>(
            array,
            options,
            "array downcast to Int64Array failed",
        ),
        DataType::UInt8 => downcast_and_encode::<F, UInt8Array>(
            array,
            options,
            "array downcast to UInt8Array failed",
        ),
        DataType::UInt16 => downcast_and_encode::<F, UInt16Array>(
            array,
            options,
            "array downcast to UInt16Array failed",
        ),
        DataType::UInt32 => downcast_and_encode::<F, UInt32Array>(
            array,
            options,
            "array downcast to UInt32Array failed",
        ),
        DataType::UInt64 => downcast_and_encode::<F, UInt64Array>(
            array,
            options,
            "array downcast to UInt64Array failed",
        ),
        DataType::Float16 => downcast_and_encode::<F, Float16Array>(
            array,
            options,
            "array downcast to Float16Array failed",
        ),
        DataType::Float32 => downcast_and_encode::<F, Float32Array>(
            array,
            options,
            "array downcast to Float32Array failed",
        ),
        DataType::Float64 => downcast_and_encode::<F, Float64Array>(
            array,
            options,
            "array downcast to Float64Array failed",
        ),
        DataType::Timestamp(unit, _) => match unit {
            TimeUnit::Second => downcast_and_encode::<F, TimestampSecondArray>(
                array,
                options,
                "array downcast to TimestampSecondArray failed",
            ),
            TimeUnit::Millisecond => downcast_and_encode::<F, TimestampMillisecondArray>(
                array,
                options,
                "array downcast to TimestampMillisecondArray failed",
            ),
            TimeUnit::Microsecond => downcast_and_encode::<F, TimestampMicrosecondArray>(
                array,
                options,
                "array downcast to TimestampMicrosecondArray failed",
            ),
            TimeUnit::Nanosecond => downcast_and_encode::<F, TimestampNanosecondArray>(
                array,
                options,
                "array downcast to TimestampNanosecondArray failed",
            ),
        },
        DataType::Date32 => downcast_and_encode::<F, Date32Array>(
            array,
            options,
            "array downcast to Date32Array failed",
        ),
        DataType::Date64 => downcast_and_encode::<F, Date64Array>(
            array,
            options,
            "array downcast to Date64Array failed",
        ),
        DataType::Time32(unit) => match unit {
            TimeUnit::Second => downcast_and_encode::<F, Time32SecondArray>(
                array,
                options,
                "array downcast to Time32SecondArray failed",
            ),
            TimeUnit::Millisecond => downcast_and_encode::<F, Time32MillisecondArray>(
                array,
                options,
                "array downcast to Time32MillisecondArray failed",
            ),
            _ => Err(EncodeError::TypeNotSupported(format!(
                "Time32 unit {unit:?} is not supported"
            ))),
        },
        DataType::Time64(unit) => match unit {
            TimeUnit::Microsecond => downcast_and_encode::<F, Time64MicrosecondArray>(
                array,
                options,
                "array downcast to Time64MicrosecondArray failed",
            ),
            TimeUnit::Nanosecond => downcast_and_encode::<F, Time64NanosecondArray>(
                array,
                options,
                "array downcast to Time64NanosecondArray failed",
            ),
            _ => Err(EncodeError::TypeNotSupported(format!(
                "Time64 unit {unit:?} is not supported"
            ))),
        },
        DataType::Duration(unit) => match unit {
            TimeUnit::Second => downcast_and_encode::<F, DurationSecondArray>(
                array,
                options,
                "array downcast to DurationSecondArray failed",
            ),
            TimeUnit::Millisecond => downcast_and_encode::<F, DurationMillisecondArray>(
                array,
                options,
                "array downcast to DurationMillisecondArray failed",
            ),
            TimeUnit::Microsecond => downcast_and_encode::<F, DurationMicrosecondArray>(
                array,
                options,
                "array downcast to DurationMicrosecondArray failed",
            ),
            TimeUnit::Nanosecond => downcast_and_encode::<F, DurationNanosecondArray>(
                array,
                options,
                "array downcast to DurationNanosecondArray failed",
            ),
        },
        DataType::Interval(unit) => match unit {
            IntervalUnit::YearMonth => downcast_and_encode::<F, IntervalYearMonthArray>(
                array,
                options,
                "array downcast to IntervalYearMonthArray failed",
            ),
            IntervalUnit::DayTime => downcast_and_encode::<F, IntervalDayTimeArray>(
                array,
                options,
                "array downcast to IntervalDayTimeArray failed",
            ),
            IntervalUnit::MonthDayNano => downcast_and_encode::<F, IntervalMonthDayNanoArray>(
                array,
                options,
                "array downcast to IntervalMonthDayNanoArray failed",
            ),
        },
        DataType::Binary => downcast_and_encode::<F, BinaryArray>(
            array,
            options,
            "array downcast to BinaryArray failed",
        ),
        DataType::LargeBinary => downcast_and_encode::<F, LargeBinaryArray>(
            array,
            options,
            "array downcast to LargeBinaryArray failed",
        ),
        DataType::BinaryView => downcast_and_encode::<F, BinaryViewArray>(
            array,
            options,
            "array downcast to BinaryViewArray failed",
        ),
        DataType::FixedSizeBinary(_) => downcast_and_encode::<F, FixedSizeBinaryArray>(
            array,
            options,
            "array downcast to FixedSizeBinaryArray failed",
        ),
        DataType::Utf8 => downcast_and_encode::<F, StringArray>(
            array,
            options,
            "array downcast to StringArray failed",
        ),
        DataType::LargeUtf8 => downcast_and_encode::<F, LargeStringArray>(
            array,
            options,
            "array downcast to LargeStringArray failed",
        ),
        DataType::Utf8View => downcast_and_encode::<F, StringViewArray>(
            array,
            options,
            "array downcast to StringViewArray failed",
        ),
        DataType::List(_) => downcast_and_encode::<F, ListArray>(
            array,
            options,
            "array downcast to ListArray failed",
        ),
        DataType::LargeList(_) => downcast_and_encode::<F, LargeListArray>(
            array,
            options,
            "array downcast to LargeListArray failed",
        ),
        DataType::ListView(_) => downcast_and_encode::<F, ListViewArray>(
            array,
            options,
            "array downcast to ListViewArray failed",
        ),
        DataType::LargeListView(_) => downcast_and_encode::<F, LargeListViewArray>(
            array,
            options,
            "array downcast to LargeListViewArray failed",
        ),
        DataType::FixedSizeList(..) => downcast_and_encode::<F, FixedSizeListArray>(
            array,
            options,
            "array downcast to FixedSizeListArray failed",
        ),
        DataType::Struct(_) => downcast_and_encode::<F, StructArray>(
            array,
            options,
            "array downcast to StructArray failed",
        ),
        DataType::Union(..) => downcast_and_encode::<F, UnionArray>(
            array,
            options,
            "array downcast to UnionArray failed",
        ),
        DataType::Dictionary(key_type, _) => match key_type.as_ref() {
            DataType::Int8 => downcast_and_encode::<F, Int8DictionaryArray>(
                array,
                options,
                "array downcast to Int8DictionaryArray failed",
            ),
            DataType::Int16 => downcast_and_encode::<F, Int16DictionaryArray>(
                array,
                options,
                "array downcast to Int16DictionaryArray failed",
            ),
            DataType::Int32 => downcast_and_encode::<F, Int32DictionaryArray>(
                array,
                options,
                "array downcast to Int32DictionaryArray failed",
            ),
            DataType::Int64 => downcast_and_encode::<F, Int64DictionaryArray>(
                array,
                options,
                "array downcast to Int64DictionaryArray failed",
            ),
            DataType::UInt8 => downcast_and_encode::<F, UInt8DictionaryArray>(
                array,
                options,
                "array downcast to UInt8DictionaryArray failed",
            ),
            DataType::UInt16 => downcast_and_encode::<F, UInt16DictionaryArray>(
                array,
                options,
                "array downcast to UInt16DictionaryArray failed",
            ),
            DataType::UInt32 => downcast_and_encode::<F, UInt32DictionaryArray>(
                array,
                options,
                "array downcast to UInt32DictionaryArray failed",
            ),
            DataType::UInt64 => downcast_and_encode::<F, UInt64DictionaryArray>(
                array,
                options,
                "array downcast to UInt64DictionaryArray failed",
            ),
            other => Err(EncodeError::TypeNotSupported(format!(
                "Dictionary key type {other} is not supported"
            ))),
        },
        DataType::Map(..) => {
            downcast_and_encode::<F, MapArray>(array, options, "array downcast to MapArray failed")
        }
        DataType::Decimal128(..) => downcast_and_encode::<F, Decimal128Array>(
            array,
            options,
            "array downcast to Decimal128Array failed",
        ),
        DataType::Decimal256(..) => downcast_and_encode::<F, Decimal256Array>(
            array,
            options,
            "array downcast to Decimal256Array failed",
        ),
        DataType::RunEndEncoded(run_ends, _) => match run_ends.data_type() {
            DataType::Int16 => downcast_and_encode::<F, Int16RunArray>(
                array,
                options,
                "array downcast to Int16RunArray failed",
            ),
            DataType::Int32 => downcast_and_encode::<F, Int32RunArray>(
                array,
                options,
                "array downcast to Int32RunArray failed",
            ),
            DataType::Int64 => downcast_and_encode::<F, Int64RunArray>(
                array,
                options,
                "array downcast to Int64RunArray failed",
            ),
            other => Err(EncodeError::TypeNotSupported(format!(
                "Run-end index type {other} is not supported"
            ))),
        },
    }
}
