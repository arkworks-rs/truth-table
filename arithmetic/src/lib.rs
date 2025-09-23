//! This crate provides a set of tools for arithmetizing (encoding) and
//! de-arithmetizing (decoding) data-structures related to databases; i.e.
//! tables, columns, data tpypes, etc.
//! Arithmetization is the process of converting a data structure into algebraic
//! objects used in proof-systems , like polynomials.

///////// Modules /////////
pub mod col;
pub mod errors;
pub mod table;
///////// Imports /////////
use ark_ff::PrimeField;
use datafusion::arrow::{
    array::{
        ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Date64Array,
        Decimal128Array, Decimal256Array, DurationMicrosecondArray, DurationMillisecondArray,
        DurationNanosecondArray, DurationSecondArray, FixedSizeBinaryArray, FixedSizeListArray,
        Float16Array, Float32Array, Float64Array, Int16Array, Int16DictionaryArray, Int16RunArray,
        Int32Array, Int32DictionaryArray, Int32RunArray, Int64Array, Int64DictionaryArray,
        Int64RunArray, Int8Array, Int8DictionaryArray, IntervalDayTimeArray,
        IntervalMonthDayNanoArray, IntervalYearMonthArray, LargeBinaryArray, LargeListArray,
        LargeListViewArray, LargeStringArray, ListArray, ListViewArray, MapArray, NullArray,
        StringArray, StringViewArray, StructArray, Time32MillisecondArray, Time32SecondArray,
        Time64MicrosecondArray, Time64NanosecondArray, TimestampMicrosecondArray,
        TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt16Array,
        UInt16DictionaryArray, UInt32Array, UInt32DictionaryArray, UInt64Array,
        UInt64DictionaryArray, UInt8Array, UInt8DictionaryArray, UnionArray,
    },
    datatypes::{DataType, IntervalUnit, TimeUnit},
};

use crate::{col::ColAdapter, errors::EncodeError};

#[tracing::instrument(level = "trace", skip_all)]
pub fn encode_arrow_array_to_field<F: PrimeField>(
    array: &ArrayRef,
) -> Result<Vec<Vec<F>>, EncodeError> {
    fn downcast_and_encode<F: PrimeField, A: ColAdapter<F> + 'static>(
        array: &ArrayRef,
        err_msg: &'static str,
    ) -> Result<Vec<Vec<F>>, EncodeError> {
        array.as_any().downcast_ref::<A>().expect(err_msg).encode()
    }

    match array.data_type() {
        DataType::Null => {
            downcast_and_encode::<F, NullArray>(array, "array downcast to NullArray failed")
        },
        DataType::Boolean => {
            downcast_and_encode::<F, BooleanArray>(array, "array downcast to BooleanArray failed")
        },
        DataType::Int8 => {
            downcast_and_encode::<F, Int8Array>(array, "array downcast to Int8Array failed")
        },
        DataType::Int16 => {
            downcast_and_encode::<F, Int16Array>(array, "array downcast to Int16Array failed")
        },
        DataType::Int32 => {
            downcast_and_encode::<F, Int32Array>(array, "array downcast to Int32Array failed")
        },
        DataType::Int64 => {
            downcast_and_encode::<F, Int64Array>(array, "array downcast to Int64Array failed")
        },
        DataType::UInt8 => {
            downcast_and_encode::<F, UInt8Array>(array, "array downcast to UInt8Array failed")
        },
        DataType::UInt16 => {
            downcast_and_encode::<F, UInt16Array>(array, "array downcast to UInt16Array failed")
        },
        DataType::UInt32 => {
            downcast_and_encode::<F, UInt32Array>(array, "array downcast to UInt32Array failed")
        },
        DataType::UInt64 => {
            downcast_and_encode::<F, UInt64Array>(array, "array downcast to UInt64Array failed")
        },
        DataType::Float16 => {
            downcast_and_encode::<F, Float16Array>(array, "array downcast to Float16Array failed")
        },
        DataType::Float32 => {
            downcast_and_encode::<F, Float32Array>(array, "array downcast to Float32Array failed")
        },
        DataType::Float64 => {
            downcast_and_encode::<F, Float64Array>(array, "array downcast to Float64Array failed")
        },
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
        },
        DataType::Date64 => {
            downcast_and_encode::<F, Date64Array>(array, "array downcast to Date64Array failed")
        },
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
        },
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
        },
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
        },
        DataType::LargeList(_) => downcast_and_encode::<F, LargeListArray>(
            array,
            "array downcast to LargeListArray failed",
        ),
        DataType::ListView(_) => {
            downcast_and_encode::<F, ListViewArray>(array, "array downcast to ListViewArray failed")
        },
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
        },
        DataType::Union(..) => {
            downcast_and_encode::<F, UnionArray>(array, "array downcast to UnionArray failed")
        },
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
        },
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
        other => Err(EncodeError::TypeNotSupported(other.to_string())),
    }
}
