use ark_ff::PrimeField;
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
