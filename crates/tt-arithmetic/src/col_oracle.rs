use ark_piop::SnarkBackend;
use ark_piop::verifier::{ArgVerifier, structs::oracle::TrackedOracle};
use datafusion::arrow::datatypes::FieldRef;
use derivative::Derivative;
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// An abstraction of an oracle to a tracked arithmetized column in dbSNARK
/// a tracked arithmetized column is represented by two polynomials: A data
/// tracked polynomial, an activator tracked polynomial If the activator
/// tracked polynomial is None, all the rows are active, and an optional
/// FieldRef
pub struct TrackedColOracle<B: SnarkBackend> {
    /// A tracked oracle representing the column values
    data_tracked_oracle: TrackedOracle<B>,
    /// A tracked (supposedly) oracle representing the activator of the
    /// column If None, all the rows are active
    /// If some, only the rows where the activator oracle is one are active
    activator_tracked_oracle: Option<TrackedOracle<B>>,
    /// The field reference of the column in the original schema, if any
    field_ref: Option<FieldRef>,
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedColOracle<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedColOracle")
            .field("log_size", &self.log_size())
            .field("has_activator", &self.activator_tracked_oracle.is_some())
            .field("field_ref", &self.field_ref)
            .finish()
    }
}

impl<B: SnarkBackend> TrackedColOracle<B> {
    /// Creates a new tracked column Oracle
    pub fn new(
        data_tracked_oracle: TrackedOracle<B>,
        activator_tracked_oracle: Option<TrackedOracle<B>>,
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
        data_tracked_oracle: &TrackedOracle<B>,
        activator_tracked_oracle: &Option<TrackedOracle<B>>,
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
    pub fn data_tracked_oracle(&self) -> TrackedOracle<B> {
        self.data_tracked_oracle.clone()
    }
    /// Returns the activator tracked oracle of the column
    pub fn activator_tracked_oracle(&self) -> Option<TrackedOracle<B>> {
        self.activator_tracked_oracle.clone()
    }

    /// Returns the field reference of the tracked column oracle in the original
    /// schema, if any
    pub fn field_ref(&self) -> Option<FieldRef> {
        self.field_ref.clone()
    }

    /// Returns a reference to the tracker of the tracked column
    pub fn tracker_ref(&self) -> ArgVerifier<B> {
        // We have the guarantee at construction that activator tracked also agrees
        ArgVerifier::new_from_tracker_rc(self.data_tracked_oracle.tracker().clone())
    }

    /// Returns the effective tracked oracle of the column, which is the product
    /// of the activator and the column polynomial
    /// Note that the non-activated elements are zeroed out, hence
    /// indistinguishable from the actual zero elements
    pub fn activated_data_tracked_oracle(&self) -> TrackedOracle<B> {
        match &self.activator_tracked_oracle {
            Some(activator) => &self.data_tracked_oracle * activator,
            None => self.data_tracked_oracle.clone(),
        }
    }

    /// Pretty-print the tracked column oracle by showing the column names.
    pub fn pretty_string(&self) -> String {
        let base_name = self
            .field_ref
            .as_ref()
            .map(|field| {
                let name = field.name();
                if name.is_empty() {
                    "-".to_string()
                } else {
                    name.to_string()
                }
            })
            .unwrap_or_else(|| "-".to_string());

        let mut headers = Vec::with_capacity(2);
        headers.push(base_name.clone());

        if self.activator_tracked_oracle.is_some() {
            headers.push(format!("{base_name} (activator)"));
        }

        if headers.is_empty() {
            return "TrackedColOracle<empty>".to_string();
        }

        let widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
        let mut out = String::new();
        out.push_str(&border_line(&widths));
        out.push_str(&row_line(&headers, &widths));
        out.push_str(&border_line(&widths));
        out
    }
}

fn border_line(widths: &[usize]) -> String {
    let mut line = String::new();
    line.push('+');
    for width in widths {
        line.push_str(&"-".repeat(width + 2));
        line.push('+');
    }
    line.push('\n');
    line
}

fn row_line(values: &[String], widths: &[usize]) -> String {
    let mut line = String::new();
    line.push('|');

    for (value, width) in values.iter().zip(widths.iter()) {
        line.push(' ');
        line.push_str(value);
        if value.len() < *width {
            line.push_str(&" ".repeat(*width - value.len()));
        }
        line.push(' ');
        line.push('|');
    }

    line.push('\n');
    line
}
