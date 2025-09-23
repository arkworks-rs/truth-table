///////// Imports /////////
use crate::errors::EncodeError;
use ark_ff::PrimeField;
use datafusion::arrow::{
    array::{
        Array, ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Date64Array,
        Decimal128Array, Decimal256Array, DictionaryArray, DurationMicrosecondArray,
        DurationMillisecondArray, DurationNanosecondArray, DurationSecondArray,
        FixedSizeBinaryArray, FixedSizeListArray, Float16Array, Float32Array, Float64Array,
        Int16Array, Int16DictionaryArray, Int16RunArray, Int32Array, Int32DictionaryArray,
        Int32RunArray, Int64Array, Int64DictionaryArray, Int64RunArray, Int8Array,
        Int8DictionaryArray, IntervalDayTimeArray, IntervalMonthDayNanoArray,
        IntervalYearMonthArray, LargeBinaryArray, LargeListArray, LargeListViewArray,
        LargeStringArray, ListArray, ListViewArray, MapArray, NullArray, StringArray,
        StringViewArray, StructArray, Time32MillisecondArray, Time32SecondArray,
        Time64MicrosecondArray, Time64NanosecondArray, TimestampMicrosecondArray,
        TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt16Array,
        UInt16DictionaryArray, UInt32Array, UInt32DictionaryArray, UInt64Array,
        UInt64DictionaryArray, UInt8Array, UInt8DictionaryArray, UnionArray,
    },
    datatypes::{DataType, IntervalUnit, TimeUnit},
};
/// A trait for encoding types into PrimeField elements.
pub trait Encodable<F: PrimeField>: Sized {
    fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError>;
    fn decode(field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError>;
}

fn field_element_byte_capacity<F: PrimeField>() -> usize {
    let bits = F::MODULUS_BIT_SIZE as usize;
    let bytes = (bits + 7) / 8;
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

        for col_idx in 0..columns.len() {
            let value = row_fields.get(col_idx).copied().unwrap_or_else(F::zero);
            columns[col_idx].push(value);
        }
    }

    if columns.is_empty() {
        vec![Vec::new()]
    } else {
        columns
    }
}

macro_rules! impl_col_adapter_map {
    ($array_ty:ty, $map:expr) => {
        impl<F: PrimeField> Encodable<F> for $array_ty {
            fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError> {
                Ok(collect_by_columns(self.len(), |idx| {
                    if self.is_null(idx) {
                        vec![F::zero()]
                    } else {
                        vec![$map(self.value(idx))]
                    }
                }))
            }

            fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
                todo!("Decoding {} is not implemented yet", stringify!($array_ty));
            }
        }
    };
}

macro_rules! impl_col_adapter_map_with_index {
    ($array_ty:ty, $map:expr) => {
        impl<F: PrimeField> Encodable<F> for $array_ty {
            fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError> {
                Ok(collect_by_columns(self.len(), |idx| {
                    if self.is_null(idx) {
                        Vec::new()
                    } else {
                        $map(self, idx)
                    }
                }))
            }

            fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
                todo!("Decoding {} is not implemented yet", stringify!($array_ty));
            }
        }
    };
}

macro_rules! impl_col_adapter_unsupported {
    ($array_ty:ty, $name:expr) => {
        impl<F: PrimeField> Encodable<F> for $array_ty {
            fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError> {
                Err(EncodeError::TypeNotSupported($name.to_string()))
            }

            fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
                todo!("Decoding {} is not implemented yet", stringify!($array_ty));
            }
        }
    };
}

impl<F: PrimeField> Encodable<F> for NullArray {
    fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError> {
        Ok(vec![vec![F::zero(); self.len()]])
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!("Decoding {} is not implemented yet", stringify!(NullArray));
    }
}

impl_col_adapter_map!(BooleanArray, |v| if v { F::one() } else { F::zero() });

impl_col_adapter_map!(Int8Array, |v| F::from(v as i128));
impl_col_adapter_map!(Int16Array, |v| F::from(v as i128));
impl_col_adapter_map!(Int32Array, |v| F::from(v as i128));
impl_col_adapter_map!(Int64Array, |v| F::from(v as i128));

impl_col_adapter_map!(UInt8Array, |v| F::from(v as u64));
impl_col_adapter_map!(UInt16Array, |v| F::from(v as u64));
impl_col_adapter_map!(UInt32Array, |v| F::from(v as u64));
impl_col_adapter_map!(UInt64Array, |v| F::from(v));

impl_col_adapter_map!(Float16Array, |v: <datafusion::arrow::datatypes::Float16Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_bits().to_le_bytes()
));
impl_col_adapter_map!(Float32Array, |v: <datafusion::arrow::datatypes::Float32Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));
impl_col_adapter_map!(Float64Array, |v: <datafusion::arrow::datatypes::Float64Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));

impl_col_adapter_map!(TimestampSecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampMillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampMicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(TimestampNanosecondArray, |v| F::from(v as i128));

impl_col_adapter_map!(Date32Array, |v| F::from(v as i128));
impl_col_adapter_map!(Date64Array, |v| F::from(v as i128));

impl_col_adapter_map!(Time32SecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time32MillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time64MicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(Time64NanosecondArray, |v| F::from(v as i128));

impl_col_adapter_map!(DurationSecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationMillisecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationMicrosecondArray, |v| F::from(v as i128));
impl_col_adapter_map!(DurationNanosecondArray, |v| F::from(v as i128));

impl_col_adapter_map!(IntervalYearMonthArray, |v| F::from(v as i128));

impl_col_adapter_map!(Decimal128Array, |v: <datafusion::arrow::datatypes::Decimal128Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));
impl_col_adapter_map!(Decimal256Array, |v: <datafusion::arrow::datatypes::Decimal256Type as datafusion::arrow::datatypes::ArrowPrimitiveType>::Native| F::from_le_bytes_mod_order(
    &v.to_le_bytes()
));

impl_col_adapter_map_with_index!(BinaryArray, |array: &BinaryArray, idx| {
    encode_bytes_to_fields::<F>(array.value(idx))
});
impl_col_adapter_map_with_index!(LargeBinaryArray, |array: &LargeBinaryArray, idx| {
    encode_bytes_to_fields::<F>(array.value(idx))
});
impl_col_adapter_map_with_index!(BinaryViewArray, |array: &BinaryViewArray, idx| {
    encode_bytes_to_fields::<F>(array.value(idx))
});

impl_col_adapter_map_with_index!(FixedSizeBinaryArray, |array: &FixedSizeBinaryArray, idx| {
    encode_bytes_to_fields::<F>(array.value(idx))
});

impl_col_adapter_map_with_index!(StringArray, |array: &StringArray, idx| {
    encode_bytes_to_fields::<F>(array.value(idx).as_bytes())
});
impl_col_adapter_map_with_index!(LargeStringArray, |array: &LargeStringArray, idx| {
    encode_bytes_to_fields::<F>(array.value(idx).as_bytes())
});
impl_col_adapter_map_with_index!(StringViewArray, |array: &StringViewArray, idx| {
    encode_bytes_to_fields::<F>(array.value(idx).as_bytes())
});

impl<F: PrimeField> Encodable<F> for IntervalDayTimeArray {
    fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError> {
        Ok(collect_by_columns(self.len(), |idx| {
            if self.is_null(idx) {
                Vec::new()
            } else {
                let interval = self.value(idx);
                let mut bytes = [0u8; 8];
                bytes[..4].copy_from_slice(&interval.days.to_le_bytes());
                bytes[4..].copy_from_slice(&interval.milliseconds.to_le_bytes());
                encode_bytes_to_fields::<F>(&bytes)
            }
        }))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(IntervalDayTimeArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for IntervalMonthDayNanoArray {
    fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError> {
        Ok(collect_by_columns(self.len(), |idx| {
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
        }))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(IntervalMonthDayNanoArray)
        );
    }
}

impl_col_adapter_unsupported!(ListArray, "List");
impl_col_adapter_unsupported!(LargeListArray, "LargeList");
impl_col_adapter_unsupported!(ListViewArray, "ListView");
impl_col_adapter_unsupported!(LargeListViewArray, "LargeListView");
impl_col_adapter_unsupported!(FixedSizeListArray, "FixedSizeList");
impl_col_adapter_unsupported!(StructArray, "Struct");
impl_col_adapter_unsupported!(UnionArray, "Union");
impl_col_adapter_unsupported!(MapArray, "Map");

impl<F: PrimeField, K> Encodable<F> for DictionaryArray<K>
where
    K: datafusion::arrow::datatypes::ArrowDictionaryKeyType,
{
    fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError> {
        Err(EncodeError::TypeNotSupported("Dictionary".to_string()))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(DictionaryArray<K>)
        );
    }
}

impl_col_adapter_unsupported!(Int16RunArray, "RunEndEncoded");
impl_col_adapter_unsupported!(Int32RunArray, "RunEndEncoded");
impl_col_adapter_unsupported!(Int64RunArray, "RunEndEncoded");

#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(
        len = array.len(),
        dtype = %array.data_type()   // use % for Display, ? for Debug
    )
)]
pub fn encode_arrow_array_to_field<F: PrimeField>(
    array: &ArrayRef,
) -> Result<Vec<Vec<F>>, EncodeError> {
    fn downcast_and_encode<F: PrimeField, A: Encodable<F> + 'static>(
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
