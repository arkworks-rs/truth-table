use std::{collections::HashSet, fmt};

use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::{structs::polynomial::TrackedPoly, Prover},
};
use datafusion::arrow::datatypes::FieldRef;
use derivative::Derivative;

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
/// An abstraction of tracked arithmetized column in dbSNARK
/// a tracked arithmetized column is represented by two polynomials: A data
/// tracked polynomial, an activator tracked polynomial If the activator
/// tracked polynomial is None, all the rows are active, and an optional
/// FieldRef
pub struct TrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// A tracked polynomial representing the column values
    data_tracked_poly: TrackedPoly<F, MvPCS, UvPCS>,

    /// A tracked (supposedly) polynomial representing the activator of the
    /// column If None, all the rows are active
    /// If some, only the rows where the activator polynomial is one are active
    activator_tracked_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,

    /// The field reference of the column in the original schema, if any
    field_ref: Option<FieldRef>,
}

impl<F, MvPCS, UvPCS> core::fmt::Debug for TrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedCol")
            .field("log_size", &self.log_size())
            .field("has_activator", &self.activator_tracked_poly.is_some())
            .field("field_ref", &self.field_ref)
            .finish()
    }
}

impl<F, MvPCS, UvPCS> fmt::Display for TrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field_name = self
            .field_ref
            .as_ref()
            .map(|field| field.name().to_string())
            .unwrap_or_else(|| "<unnamed>".to_string());

        let data_evals = self.data_tracked_poly.evaluations();
        let data_repr = if data_evals.is_empty() {
            "[]".to_string()
        } else if data_evals.len() <= 2 {
            format!(
                "[{}]",
                data_evals
                    .iter()
                    .map(|v| format!("{:?}", v))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            format!(
                "{:?} ... {:?}",
                data_evals.first().unwrap(),
                data_evals.last().unwrap()
            )
        };

        let activator_repr = match &self.activator_tracked_poly {
            Some(poly) => {
                let evals = poly.evaluations();
                if evals.len() <= 10 {
                    format!(
                        "[{}]",
                        evals
                            .iter()
                            .map(|v| format!("{:?}", v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                } else {
                    let mut values = Vec::with_capacity(11);
                    values.extend(evals.iter().take(5).map(|val| format!("{:?}", val)));
                    values.push("...".to_string());
                    values.extend(
                        evals
                            .iter()
                            .rev()
                            .take(5)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .map(|val| format!("{:?}", val)),
                    );
                    format!("[{}]", values.join(", "))
                }
            },
            None => "none".to_string(),
        };

        write!(
            f,
            "{}: data={}, activator={}",
            field_name, data_repr, activator_repr
        )
    }
}

impl<F, MvPCS, UvPCS> TrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Creates a new tracked column
    pub fn new(
        data_tracked_poly: TrackedPoly<F, MvPCS, UvPCS>,
        activator_tracked_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&data_tracked_poly, &activator_tracked_poly, &field_ref);
        }
        Self {
            data_tracked_poly,
            activator_tracked_poly,
            field_ref,
        }
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        data_tracked_poly: &TrackedPoly<F, MvPCS, UvPCS>,
        activator_tracked_poly: &Option<TrackedPoly<F, MvPCS, UvPCS>>,
        _field_ref: &Option<FieldRef>,
    ) {
        if activator_tracked_poly.is_some() {
            let activator = activator_tracked_poly.as_ref().unwrap();
            debug_assert_eq!(data_tracked_poly.log_size(), activator.log_size());
            debug_assert!(data_tracked_poly.same_tracker(activator));
        }
    }

    /// Returns the log size of the tracked polynomials
    pub fn log_size(&self) -> usize {
        self.data_tracked_poly.log_size()
    }

    /// Returns the data tracked polynomial of the column
    pub fn data_tracked_poly(&self) -> TrackedPoly<F, MvPCS, UvPCS> {
        self.data_tracked_poly.clone()
    }

    /// Returns the activator tracked polynomial of the column
    pub fn activator_tracked_poly(&self) -> Option<TrackedPoly<F, MvPCS, UvPCS>> {
        self.activator_tracked_poly.clone()
    }
    /// Returns the field reference of the tracked column in the original
    /// schema, if any
    pub fn field_ref(&self) -> Option<FieldRef> {
        self.field_ref.clone()
    }

    /// Returns a reference to the tracker of the tracked column
    pub fn tracker_ref(&self) -> Prover<F, MvPCS, UvPCS> {
        // We have the guarantee at construction that activator tracked also agrees
        Prover::new_from_tracker_rc(self.data_tracked_poly.tracker())
    }

    /// Returns the effective tracked polynomial of the column, which is the
    /// product of the activator and the column polynomial
    /// Note that the non-activated elements are zeroed out, hence
    /// indistinguishable from the actual zero elements
    pub fn activated_data_tracked_poly(&self) -> TrackedPoly<F, MvPCS, UvPCS> {
        match &self.activator_tracked_poly {
            Some(activator) => &self.data_tracked_poly * activator,
            None => self.data_tracked_poly.clone(),
        }
    }

    /// Returns an iterator over the activated data elements
    /// Useful for testing and debugging
    pub fn effective_iter(&self) -> impl IntoIterator<Item = F> {
        match &self.activator_tracked_poly {
            Some(activator) => self
                .data_tracked_poly
                .evaluations()
                .into_iter()
                .zip(activator.evaluations())
                .filter(|(_, activator)| *activator != F::zero())
                .map(|(data, _)| data)
                .collect::<Vec<F>>(),
            None => self.data_tracked_poly.evaluations(),
        }
    }

    /// Returns a hashset of the activated data elements
    /// Useful for testing and debugging
    pub fn effective_hashset(&self) -> HashSet<F> {
        self.effective_iter()
            .into_iter()
            .collect::<std::collections::HashSet<F>>()
    }

    /// Pretty-print the tracked column, optionally showing the activator column.
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
        let mut columns: Vec<Vec<String>> = Vec::with_capacity(2);

        headers.push(base_name.clone());
        columns.push(
            self.data_tracked_poly
                .evaluations()
                .into_iter()
                .map(|val| abbreviate_field_value(&format!("{}", val)))
                .collect(),
        );

        if let Some(activator) = &self.activator_tracked_poly {
            headers.push(format!("{base_name} (activator)"));
            columns.push(
                activator
                    .evaluations()
                    .into_iter()
                    .map(|val| abbreviate_field_value(&format!("{}", val)))
                    .collect(),
            );
        }

        if headers.is_empty() {
            return "TrackedCol<empty>".to_string();
        }

        let widths: Vec<usize> = headers
            .iter()
            .enumerate()
            .map(|(idx, header)| {
                let col_width = columns
                    .get(idx)
                    .and_then(|col| col.iter().map(|val| val.len()).max())
                    .unwrap_or(0);
                std::cmp::max(header.len(), col_width)
            })
            .collect();

        let num_rows = columns.first().map(|col| col.len()).unwrap_or(0);
        let mut out = String::new();
        out.push_str(&border_line(&widths));
        out.push_str(&row_line(&headers, &widths));
        out.push_str(&border_line(&widths));

        for row in 0..num_rows {
            let row_values: Vec<String> = columns
                .iter()
                .map(|col| col.get(row).cloned().unwrap_or_else(|| "-".to_string()))
                .collect();
            out.push_str(&row_line(&row_values, &widths));
        }

        out.push_str(&border_line(&widths));
        out
    }
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for TrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Clone,
    UvPCS: PCS<F, Poly = LDE<F>> + Clone,
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            data_tracked_poly: self.data_tracked_poly.deep_clone(new_prover.clone()),
            activator_tracked_poly: self
                .activator_tracked_poly
                .as_ref()
                .map(|activator| activator.deep_clone(new_prover)),
            field_ref: self.field_ref.clone(),
        }
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

fn abbreviate_field_value(value: &str) -> String {
    const PREFIX_LEN: usize = 3;
    const SUFFIX_LEN: usize = 2;

    if value.len() <= PREFIX_LEN + SUFFIX_LEN {
        value.to_string()
    } else {
        let prefix = &value[..PREFIX_LEN];
        let suffix = &value[value.len() - SUFFIX_LEN..];
        format!("{prefix}...{suffix}")
    }
}
