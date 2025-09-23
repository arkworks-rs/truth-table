use std::collections::HashSet;

use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::{structs::polynomial::TrackedPoly, Prover},
    verifier::{structs::oracle::TrackedOracle, Verifier},
};
use datafusion::arrow::{
    array::{
        Array, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Date64Array,
        Decimal128Array, Decimal256Array, DictionaryArray, DurationMicrosecondArray,
        DurationMillisecondArray, DurationNanosecondArray, DurationSecondArray,
        FixedSizeBinaryArray, FixedSizeListArray, Float16Array, Float32Array, Float64Array,
        Int16Array, Int16RunArray, Int32Array, Int32RunArray, Int64Array, Int64RunArray, Int8Array,
        IntervalDayTimeArray, IntervalMonthDayNanoArray, IntervalYearMonthArray, LargeBinaryArray,
        LargeListArray, LargeListViewArray, LargeStringArray, ListArray, ListViewArray, MapArray,
        NullArray, StringArray, StringViewArray, StructArray, Time32MillisecondArray,
        Time32SecondArray, Time64MicrosecondArray, Time64NanosecondArray,
        TimestampMicrosecondArray, TimestampMillisecondArray, TimestampNanosecondArray,
        TimestampSecondArray, UInt16Array, UInt32Array, UInt64Array, UInt8Array, UnionArray,
    },
    datatypes::DataType,
};
use derivative::Derivative;

use crate::errors::EncodeError;

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
/// An abstraction of an arithmetized column in dbSNARK
/// an arithmetized column is represented by two polynomials: A data polynomial
/// and an activator polynomial If the activator polynomial is None, all the
/// rows are active
pub struct ArithCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The polynomial representing the column. It is the
    /// extension of the column values. Depending on the activator
    /// polynomial, a value can be active or inactive
    data_poly: TrackedPoly<F, MvPCS, UvPCS>,

    /// The activator polynomial, It evaluates to one at the indices of the
    /// active rows, and zero elsewhere. If it is None, all the rows are active
    actvtr_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,

    /// The data type of the column
    data_type: Option<DataType>,
}

// Custom Debug impl that does not require `MvPCS`/`UvPCS` to implement Debug.
impl<F, MvPCS, UvPCS> core::fmt::Debug for ArithCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArithCol")
            .field("num_vars", &self.num_vars())
            .field("has_actvtr", &self.actvtr_poly.is_some())
            .field("data_type", &self.data_type)
            .finish()
    }
}

impl<F, MvPCS, UvPCS> ArithCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Creates a new arithmetized column given a polynomial
    /// interpolating/extending the column and possibly an activator polynomial
    pub fn new(
        data_type: Option<DataType>,
        data_poly: TrackedPoly<F, MvPCS, UvPCS>,
        actvtr_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            if actvtr_poly.is_some() {
                let actvtr = actvtr_poly.as_ref().unwrap();
                assert_eq!(data_poly.log_size(), actvtr.log_size());
                assert!(data_poly.same_tracker(actvtr));
            }
        }
        Self {
            data_type,
            data_poly,
            actvtr_poly,
        }
    }

    /// Returns the number of variables of the column polynomial
    /// It is log_2 of the maximum capacity of the column
    pub fn num_vars(&self) -> usize {
        self.data_poly.log_size()
    }

    /// Returns the data polynomial of the column
    pub fn data_poly(&self) -> &TrackedPoly<F, MvPCS, UvPCS> {
        &self.data_poly
    }

    /// Returns the activator polynomial of the column
    pub fn actvtr_poly(&self) -> Option<&TrackedPoly<F, MvPCS, UvPCS>> {
        self.actvtr_poly.as_ref()
    }

    pub fn data_type(&self) -> Option<DataType> {
        self.data_type.clone()
    }

    /// Returns a reference to the tracker of the column
    pub fn tracker_ref(&self) -> Prover<F, MvPCS, UvPCS> {
        Prover::new_from_tracker_rc(self.data_poly.tracker())
    }

    /// Returns the effective polynomial of the column, which is the product of
    /// the activator and the column polynomial
    /// Note that the non-activated elements are zeroed out, hence
    /// indistinguishable from the actual zero elements
    pub fn activated_data_poly(&self) -> TrackedPoly<F, MvPCS, UvPCS> {
        match &self.actvtr_poly {
            Some(actv) => &self.data_poly * actv,
            None => self.data_poly.clone(),
        }
    }

    /// Returns an iterator over the activate data elements
    pub fn effective_iter(&self) -> impl IntoIterator<Item = F> {
        match &self.actvtr_poly {
            Some(actv) => self
                .data_poly
                .evaluations()
                .into_iter()
                .zip(actv.evaluations())
                .filter(|(_, actv)| *actv != F::zero())
                .map(|(data, _)| data)
                .collect::<Vec<F>>(),
            None => self.data_poly.evaluations(),
        }
    }

    pub fn effective_hashset(&self) -> HashSet<F> {
        self.effective_iter()
            .into_iter()
            .collect::<std::collections::HashSet<F>>()
    }
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for ArithCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Clone,
    UvPCS: PCS<F, Poly = LDE<F>> + Clone,
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            data_poly: self.data_poly.deep_clone(new_prover.clone()),
            actvtr_poly: self
                .actvtr_poly
                .as_ref()
                .map(|actv| actv.deep_clone(new_prover)),
            data_type: self.data_type.clone(),
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    PartialEq(bound = "UvPCS: PCS<F>")
)]
pub struct ColCom<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub data_type: Option<DataType>,
    pub inner: TrackedOracle<F, MvPCS, UvPCS>,
    pub actv: Option<TrackedOracle<F, MvPCS, UvPCS>>,
    pub num_vars: usize,
}
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> ColCom<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        data_type: Option<DataType>,
        inner: TrackedOracle<F, MvPCS, UvPCS>,
        actv: Option<TrackedOracle<F, MvPCS, UvPCS>>,
        num_vars: usize,
    ) -> Self {
        Self {
            data_type,
            inner,
            actv,
            num_vars,
        }
    }
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Returns the data polynomial of the column
    pub fn data_com(&self) -> &TrackedOracle<F, MvPCS, UvPCS> {
        &self.inner
    }
    /// Returns the activator polynomial of the column
    pub fn actvtr_com(&self) -> Option<&TrackedOracle<F, MvPCS, UvPCS>> {
        self.actv.as_ref()
    }

    pub fn data_type(&self) -> Option<DataType> {
        self.data_type.clone()
    }

    /// Returns a reference to the tracker of the column
    pub fn tracker_ref(&self) -> Verifier<F, MvPCS, UvPCS> {
        Verifier::new_from_tracker_rc(self.inner.tracker.clone())
    }
    /// Returns the effective polynomial of the column, which is the product of
    /// the activator and the column polynomial
    pub fn effective_comm(&self) -> TrackedOracle<F, MvPCS, UvPCS> {
        match &self.actv {
            Some(actv) => &self.inner * (actv),
            None => self.inner.clone(),
        }
    }
}

/// A trait for encoding types into PrimeField elements.
pub trait ColAdapter<F: PrimeField>: Sized {
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
        impl<F: PrimeField> ColAdapter<F> for $array_ty {
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
        impl<F: PrimeField> ColAdapter<F> for $array_ty {
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
        impl<F: PrimeField> ColAdapter<F> for $array_ty {
            fn encode(&self) -> Result<Vec<Vec<F>>, EncodeError> {
                Err(EncodeError::TypeNotSupported($name.to_string()))
            }

            fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
                todo!("Decoding {} is not implemented yet", stringify!($array_ty));
            }
        }
    };
}

impl<F: PrimeField> ColAdapter<F> for NullArray {
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

impl<F: PrimeField> ColAdapter<F> for IntervalDayTimeArray {
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

impl<F: PrimeField> ColAdapter<F> for IntervalMonthDayNanoArray {
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

impl<F: PrimeField, K> ColAdapter<F> for DictionaryArray<K>
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
