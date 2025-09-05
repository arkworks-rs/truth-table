use std::collections::HashSet;

use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::{structs::polynomial::TrackedPoly, Prover},
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::{
    array::{Int32Array, Int64Array},
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
                assert_eq!(data_poly.get_log_size(), actvtr.get_log_size());
                assert!(data_poly.same_tracker(&actvtr));
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
    pub fn get_num_vars(&self) -> usize {
        self.data_poly.get_log_size()
    }

    /// Returns the data polynomial of the column
    pub fn get_data_poly(&self) -> &TrackedPoly<F, MvPCS, UvPCS> {
        &self.data_poly
    }

    /// Returns the activator polynomial of the column
    pub fn get_actvtr_poly(&self) -> Option<&TrackedPoly<F, MvPCS, UvPCS>> {
        self.actvtr_poly.as_ref()
    }

    pub fn get_data_type(&self) -> Option<DataType> {
        self.data_type.clone()
    }

    /// Returns a reference to the tracker of the column
    pub fn get_tracker_ref(&self) -> Prover<F, MvPCS, UvPCS> {
        Prover::new_from_tracker_rc(self.data_poly.get_tracker())
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
    fn encode(&self) -> Result<Vec<F>, EncodeError>;
    fn decode(field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError>;
}

impl<F: PrimeField> ColAdapter<F> for Int32Array {
    fn encode(&self) -> Result<Vec<F>, EncodeError> {
        Ok(self.iter().filter_map(|x| x.map(|v| F::from(v))).collect())
    }

    fn decode(field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!()
    }
}

impl<F: PrimeField> ColAdapter<F> for Int64Array {
    fn encode(&self) -> Result<Vec<F>, EncodeError> {
        Ok(self.iter().filter_map(|x| x.map(|v| F::from(v))).collect())
    }

    fn decode(field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!()
    }
}
