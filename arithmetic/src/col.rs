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
