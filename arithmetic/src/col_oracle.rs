use std::collections::HashSet;

use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::{structs::polynomial::TrackedPoly, Prover},
    verifier::{structs::oracle::TrackedOracle, Verifier},
};
use datafusion::arrow::datatypes::DataType;
use derivative::Derivative;
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    PartialEq(bound = "UvPCS: PCS<F>")
)]
pub struct ArithColOracle<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
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
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> ArithColOracle<F, MvPCS, UvPCS>
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
