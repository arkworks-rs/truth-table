use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    verifier::{structs::oracle::TrackedOracle, Verifier},
};
use datafusion::arrow::datatypes::FieldRef;
use derivative::Derivative;
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    PartialEq(bound = "UvPCS: PCS<F>")
)]
/// An abstraction of an oracle to a tracked arithmetized column in dbSNARK
/// a tracked arithmetized column is represented by two polynomials: A data
/// tracked polynomial, an activator tracked polynomial If the activator
/// tracked polynomial is None, all the rows are active, and an optional
/// FieldRef
pub struct TrackedColOracle<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// A tracked oracle representing the column values
    data_tracked_oracle: TrackedOracle<F, MvPCS, UvPCS>,
    /// A tracked (supposedly) oracle representing the activator of the
    /// column If None, all the rows are active
    /// If some, only the rows where the activator oracle is one are active
    activator_tracked_oracle: Option<TrackedOracle<F, MvPCS, UvPCS>>,
    /// The field reference of the column in the original schema, if any
    field_ref: Option<FieldRef>,
}

impl<F, MvPCS, UvPCS> core::fmt::Debug for TrackedColOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedColOracle")
            .field("log_size", &self.log_size())
            .field("has_activator", &self.activator_tracked_oracle.is_some())
            .field("field_ref", &self.field_ref)
            .finish()
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> TrackedColOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Creates a new tracked column Oracle
    pub fn new(
        data_tracked_oracle: TrackedOracle<F, MvPCS, UvPCS>,
        activator_tracked_oracle: Option<TrackedOracle<F, MvPCS, UvPCS>>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&data_tracked_oracle, &activator_tracked_oracle, &field_ref);
        }
        Self {
            data_tracked_oracle,
            activator_tracked_oracle,
            field_ref,
        }
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        data_tracked_oracle: &TrackedOracle<F, MvPCS, UvPCS>,
        activator_tracked_oracle: &Option<TrackedOracle<F, MvPCS, UvPCS>>,
        _field_ref: &Option<FieldRef>,
    ) {
        if activator_tracked_oracle.is_some() {
            let activator = activator_tracked_oracle.as_ref().unwrap();
            debug_assert_eq!(data_tracked_oracle.log_size(), activator.log_size());
            debug_assert!(data_tracked_oracle.same_tracker(activator));
        }
    }

    /// Returns the log size of the tracked oracle
    pub fn log_size(&self) -> usize {
        self.data_tracked_oracle.log_size()
    }

    /// Returns the data tracked oracle of the column
    pub fn data_tracked_oracle(&self) -> TrackedOracle<F, MvPCS, UvPCS> {
        self.data_tracked_oracle.clone()
    }
    /// Returns the activator tracked oracle of the column
    pub fn activator_tracked_oracle(&self) -> Option<TrackedOracle<F, MvPCS, UvPCS>> {
        self.activator_tracked_oracle.clone()
    }

    /// Returns the field reference of the tracked column oracle in the original
    /// schema, if any
    pub fn field_ref(&self) -> Option<FieldRef> {
        self.field_ref.clone()
    }

    /// Returns a reference to the tracker of the tracked column
    pub fn tracker_ref(&self) -> Verifier<F, MvPCS, UvPCS> {
        // We have the guarantee at construction that activator tracked also agrees
        Verifier::new_from_tracker_rc(self.data_tracked_oracle.tracker().clone())
    }

    /// Returns the effective tracked oracle of the column, which is the product
    /// of the activator and the column polynomial
    /// Note that the non-activated elements are zeroed out, hence
    /// indistinguishable from the actual zero elements
    pub fn activated_data_tracked_oracle(&self) -> TrackedOracle<F, MvPCS, UvPCS> {
        match &self.activator_tracked_oracle {
            Some(activator) => &self.data_tracked_oracle * activator,
            None => self.data_tracked_oracle.clone(),
        }
    }
}
