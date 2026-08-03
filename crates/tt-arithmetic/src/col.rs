use std::fmt;
use std::sync::Arc;

use ark_ff::Zero;
use ark_piop::SnarkBackend;
use ark_piop::{
    piop::DeepClone,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
};
use datafusion::arrow::datatypes::FieldRef;
use datafusion::arrow::datatypes::{DataType, Field};
use datafusion::common::Column;
use datafusion_expr::Expr;
use derivative::Derivative;
use indexmap::{IndexMap, IndexSet};
use once_cell::sync::Lazy;

pub const ACTIVATOR_COL_NAME: &str = "__activator__";
pub const ROW_ID_COL_NAME: &str = "__row_id__";
pub static ACTIVATOR_FIELD: Lazy<FieldRef> =
    Lazy::new(|| Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, true)));
pub static ROW_ID_FIELD: Lazy<FieldRef> =
    Lazy::new(|| Arc::new(Field::new(ROW_ID_COL_NAME, DataType::Int64, true)));
pub static ACTIVATOR_EXPR: Lazy<Expr> =
    Lazy::new(|| Expr::Column(Column::from_name(ACTIVATOR_COL_NAME)));
pub static ROW_ID_EXPR: Lazy<Expr> = Lazy::new(|| Expr::Column(Column::from_name(ROW_ID_COL_NAME)));

pub fn is_system_column(name: &str) -> bool {
    name == ACTIVATOR_COL_NAME || name == ROW_ID_COL_NAME
}

/// An auxiliary polynomial belonging to a tracked column: its own data
/// poly plus the activator paired with that data.
///
/// - Row-domain aux (e.g. `__length` for strings): activator mirrors the
///   primary's activator (Some if the primary has one, None otherwise —
///   base tables without a filter have neither).
/// - Side-domain aux (e.g. `__chars`, `__orig_ind`): activator is a
///   contiguous-one polynomial over the smaller side domain — always
///   `Some`.
///
/// The row-vs-side distinction is not stored — it's derived by comparing
/// `data.log_size()` against the owning column's primary log_size. See
/// [`TrackedCol::side_segments_iter`].
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""), Debug(bound = ""))]
pub struct PolyBundle<B: SnarkBackend> {
    pub data: TrackedPoly<B>,
    pub activator: Option<TrackedPoly<B>>,
}

impl<B: SnarkBackend> PolyBundle<B> {
    /// Constructs an aux polynomial from its data and (optional) activator.
    pub fn new(data: TrackedPoly<B>, activator: Option<TrackedPoly<B>>) -> Self {
        Self { data, activator }
    }

    /// Multilinear domain size of this aux polynomial.
    pub fn log_size(&self) -> usize {
        self.data.log_size()
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// An abstraction of a tracked arithmetized column in dbSNARK.
///
/// Most columns are `SingleSegment` (one data polynomial + an optional
/// activator). Multi-aspect encodings (like strings) expand into
/// `MultiSegment`, which carries a primary polynomial plus a map of
/// auxiliary polynomials. Row-domain aux and side-domain aux live in
/// the same map — distinguished by comparing `aux.data.log_size()`
/// against the primary's log_size (row-domain aux match; side-domain
/// aux have their own smaller domain).
pub enum TrackedCol<B: SnarkBackend> {
    SingleSegment {
        /// The column's data polynomial + its (optional) activator.
        poly_bundle: PolyBundle<B>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        /// The primary (canonical) data polynomial + its activator.
        primary_poly_bundle: PolyBundle<B>,
        /// All auxiliary polynomial bundles belonging to this column,
        /// keyed by segment suffix (e.g. `__length`, `__chars`,
        /// `__orig_ind`, `__bnd`).
        aux_poly_bundles: IndexMap<String, PolyBundle<B>>,
        field_ref: Option<FieldRef>,
    },
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedCol<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SingleSegment {
                poly_bundle,
                field_ref,
            } => f
                .debug_struct("TrackedCol::SingleSegment")
                .field("log_size", &poly_bundle.log_size())
                .field("has_activator", &poly_bundle.activator.is_some())
                .field("field_ref", field_ref)
                .finish(),
            Self::MultiSegment {
                primary_poly_bundle,
                aux_poly_bundles,
                field_ref,
            } => {
                let primary_log_size = primary_poly_bundle.log_size();
                let (side_ids, row_ids): (Vec<_>, Vec<_>) = aux_poly_bundles
                    .iter()
                    .partition(|(_, aux)| aux.log_size() != primary_log_size);
                f.debug_struct("TrackedCol::MultiSegment")
                    .field("num_segments", &(1 + aux_poly_bundles.len()))
                    .field(
                        "row_aux_segments",
                        &row_ids.iter().map(|(k, _)| k).collect::<Vec<_>>(),
                    )
                    .field(
                        "side_segments",
                        &side_ids.iter().map(|(k, _)| k).collect::<Vec<_>>(),
                    )
                    .field("field_ref", field_ref)
                    .finish()
            }
        }
    }
}

impl<B: SnarkBackend> fmt::Display for TrackedCol<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field_name = self
            .field_ref()
            .map(|field| field.name().to_string())
            .unwrap_or_else(|| "<unnamed>".to_string());

        let data_repr = |poly: &TrackedPoly<B>| -> String {
            let evals = poly.evaluations();
            if evals.is_empty() {
                "[]".to_string()
            } else if evals.len() <= 2 {
                format!(
                    "[{}]",
                    evals
                        .iter()
                        .map(|v| format!("{:?}", v))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!(
                    "{:?} ... {:?}",
                    evals.first().unwrap(),
                    evals.last().unwrap()
                )
            }
        };
        let activator_repr = |poly: &Option<TrackedPoly<B>>| -> String {
            match poly {
                Some(activator) => {
                    let evals = activator.evaluations();
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
                }
                None => "none".to_string(),
            }
        };

        match self {
            Self::SingleSegment { poly_bundle, .. } => write!(
                f,
                "{}: data={}, activator={}",
                field_name,
                data_repr(&poly_bundle.data),
                activator_repr(&poly_bundle.activator),
            ),
            Self::MultiSegment {
                primary_poly_bundle,
                aux_poly_bundles,
                ..
            } => {
                writeln!(f, "{} (multi-segment):", field_name)?;
                writeln!(
                    f,
                    "  <primary>: data={}, activator={}",
                    data_repr(&primary_poly_bundle.data),
                    activator_repr(&primary_poly_bundle.activator),
                )?;
                let primary_log_size = primary_poly_bundle.log_size();
                for (sid, aux) in aux_poly_bundles.iter() {
                    if aux.log_size() != primary_log_size {
                        writeln!(
                            f,
                            "  {} (side): log_size={}",
                            sid,
                            aux.log_size(),
                        )?;
                    } else {
                        writeln!(
                            f,
                            "  {}: data={}, activator={}",
                            sid,
                            data_repr(&aux.data),
                            activator_repr(&aux.activator),
                        )?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl<B: SnarkBackend> TrackedCol<B> {
    /// Constructs a single-segment tracked column.
    pub fn new(
        data_tracked_poly: TrackedPoly<B>,
        activator_tracked_poly: Option<TrackedPoly<B>>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&data_tracked_poly, &activator_tracked_poly, &field_ref);
        }
        Self::SingleSegment {
            poly_bundle: PolyBundle::new(data_tracked_poly, activator_tracked_poly),
            field_ref,
        }
    }

    /// Constructs a multi-segment tracked column: one required primary
    /// poly bundle plus zero or more named aux poly bundles. Aux ids must
    /// be non-empty (the primary owns the empty id by convention). Row-
    /// and side-domain aux polys live in the same map — distinguished
    /// downstream by comparing `aux.data.log_size()` against primary's.
    pub fn new_multi(
        primary_poly_bundle: PolyBundle<B>,
        aux_poly_bundles_input: Vec<(String, PolyBundle<B>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let mut aux_poly_bundles: IndexMap<String, PolyBundle<B>> =
            IndexMap::with_capacity(aux_poly_bundles_input.len());
        for (sid, aux) in aux_poly_bundles_input {
            assert!(
                !sid.is_empty(),
                "MultiSegment aux segment id must be non-empty (primary owns the empty id)"
            );
            assert!(
                !aux_poly_bundles.contains_key(&sid),
                "duplicate aux segment id '{sid}' in MultiSegment column"
            );
            aux_poly_bundles.insert(sid, aux);
        }
        Self::MultiSegment {
            primary_poly_bundle,
            aux_poly_bundles,
            field_ref,
        }
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        data_tracked_poly: &TrackedPoly<B>,
        activator_tracked_poly: &Option<TrackedPoly<B>>,
        _field_ref: &Option<FieldRef>,
    ) {
        if activator_tracked_poly.is_some() {
            let activator = activator_tracked_poly.as_ref().unwrap();
            // A folded-constant poly evaluates identically on any hypercube,
            // so its stored log_size is unconstrained. Only enforce the size
            // match when both sides are non-constant.
            if !data_tracked_poly.is_constant() && !activator.is_constant() {
                debug_assert_eq!(data_tracked_poly.log_size(), activator.log_size());
            }
            debug_assert!(data_tracked_poly.same_tracker(activator));
        }
    }

    /// Returns the log size of the tracked polynomials. All row-domain
    /// segments in a multi-segment column share the same log size by
    /// construction.
    pub fn log_size(&self) -> usize {
        match self {
            Self::SingleSegment { poly_bundle, .. } => poly_bundle.log_size(),
            Self::MultiSegment {
                primary_poly_bundle,
                ..
            } => primary_poly_bundle.log_size(),
        }
    }

    /// Returns the primary data polynomial — the unique poly for a single-
    /// segment column, or the primary of a multi-segment column.
    pub fn data_tracked_poly(&self) -> TrackedPoly<B> {
        match self {
            Self::SingleSegment { poly_bundle, .. } => poly_bundle.data.clone(),
            Self::MultiSegment {
                primary_poly_bundle,
                ..
            } => primary_poly_bundle.data.clone(),
        }
    }

    /// Returns the activator polynomial paired with the primary data segment.
    pub fn activator_tracked_poly(&self) -> Option<TrackedPoly<B>> {
        match self {
            Self::SingleSegment { poly_bundle, .. } => poly_bundle.activator.clone(),
            Self::MultiSegment {
                primary_poly_bundle,
                ..
            } => primary_poly_bundle.activator.clone(),
        }
    }

    /// Returns the field reference of the column, if any.
    pub fn field_ref(&self) -> Option<FieldRef> {
        match self {
            Self::SingleSegment { field_ref, .. } | Self::MultiSegment { field_ref, .. } => {
                field_ref.clone()
            }
        }
    }

    /// Total number of polynomials in this column (primary + all aux
    /// segments, row-domain AND side-domain). Always >= 1.
    pub fn num_segments(&self) -> usize {
        match self {
            Self::SingleSegment { .. } => 1,
            Self::MultiSegment {
                aux_poly_bundles, ..
            } => 1 + aux_poly_bundles.len(),
        }
    }

    /// Iterate `(id, data, activator)` over ROW-domain segments only:
    /// primary yields `id = None`, row-aux yields `id = Some(sid)`. Side-
    /// domain aux (those whose `data.log_size()` differs from the
    /// primary's) are excluded — use
    /// [`side_segments_iter`](Self::side_segments_iter) for those.
    pub fn segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (Option<&str>, &TrackedPoly<B>, Option<&TrackedPoly<B>>)> + '_>
    {
        match self {
            Self::SingleSegment { poly_bundle, .. } => Box::new(std::iter::once((
                None,
                &poly_bundle.data,
                poly_bundle.activator.as_ref(),
            ))),
            Self::MultiSegment {
                primary_poly_bundle,
                aux_poly_bundles,
                ..
            } => {
                let primary_log_size = primary_poly_bundle.log_size();
                let primary = std::iter::once((
                    None,
                    &primary_poly_bundle.data,
                    primary_poly_bundle.activator.as_ref(),
                ));
                let aux = aux_poly_bundles
                    .iter()
                    .filter(move |(_, aux)| aux.data.log_size() == primary_log_size)
                    .map(|(sid, aux)| (Some(sid.as_str()), &aux.data, aux.activator.as_ref()));
                Box::new(primary.chain(aux))
            }
        }
    }

    /// Look up ANY aux segment (row-domain or side-domain) by id.
    /// Returns `None` if the id is not registered (including for
    /// `SingleSegment` columns, which have no aux).
    pub fn aux_segment(&self, aux_id: &str) -> Option<&PolyBundle<B>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                aux_poly_bundles, ..
            } => aux_poly_bundles.get(aux_id),
        }
    }

    /// Look up a side-domain segment specifically (returns `None` if the
    /// id resolves to a row-domain aux). Convenience over `aux_segment`
    /// for callers that assert side-ness.
    pub fn side_segment(&self, side_id: &str) -> Option<&PolyBundle<B>> {
        let primary_log_size = self.log_size();
        self.aux_segment(side_id)
            .filter(|aux| aux.data.log_size() != primary_log_size)
    }

    /// Iterate `(suffix, aux)` over every side-domain segment in this
    /// column, in insertion order. Empty for `SingleSegment` columns.
    pub fn side_segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (&str, &PolyBundle<B>)> + '_> {
        match self {
            Self::SingleSegment { .. } => Box::new(std::iter::empty()),
            Self::MultiSegment {
                primary_poly_bundle,
                aux_poly_bundles,
                ..
            } => {
                let primary_log_size = primary_poly_bundle.log_size();
                Box::new(
                    aux_poly_bundles
                        .iter()
                        .filter(move |(_, aux)| aux.data.log_size() != primary_log_size)
                        .map(|(sid, aux)| (sid.as_str(), aux)),
                )
            }
        }
    }

    /// Returns a reference to the tracker shared by all polys in this column.
    pub fn tracker_ref(&self) -> ArgProver<B> {
        let poly = match self {
            Self::SingleSegment { poly_bundle, .. } => &poly_bundle.data,
            Self::MultiSegment {
                primary_poly_bundle,
                ..
            } => &primary_poly_bundle.data,
        };
        ArgProver::new_from_tracker_rc(poly.tracker())
    }

    /// Returns the effective primary tracked polynomial: data * activator
    /// (when an activator exists), otherwise just the data poly.
    pub fn activated_data_tracked_poly(&self) -> TrackedPoly<B> {
        match self.activator_tracked_poly() {
            Some(activator) => &self.data_tracked_poly() * &activator,
            None => self.data_tracked_poly(),
        }
    }

    /// Returns a vec of the active-row primary data values.
    pub fn effective_iter(&self) -> impl IntoIterator<Item = B::F> + use<B> {
        let data = self.data_tracked_poly();
        match self.activator_tracked_poly() {
            Some(activator) => data
                .evaluations()
                .into_iter()
                .zip(activator.evaluations())
                .filter(|(_, activator)| *activator != B::F::zero())
                .map(|(data, _)| data)
                .collect::<Vec<B::F>>(),
            None => data.evaluations(),
        }
    }

    /// Returns a hashset of the activated primary data elements (for tests).
    pub fn effective_hashset(&self) -> IndexSet<B::F> {
        self.effective_iter()
            .into_iter()
            .collect::<IndexSet<B::F>>()
    }

    /// Pretty-print the tracked column (primary segment only, for brevity).
    pub fn pretty_string(&self) -> String {
        let base_name = self
            .field_ref()
            .map(|field| {
                let name = field.name();
                if name.is_empty() {
                    "-".to_string()
                } else {
                    name.to_string()
                }
            })
            .unwrap_or_else(|| "-".to_string());

        let data = self.data_tracked_poly();
        let activator = self.activator_tracked_poly();

        let mut headers = Vec::with_capacity(3);
        let mut columns: Vec<Vec<String>> = Vec::with_capacity(3);

        headers.push(base_name.clone());
        columns.push(
            data.evaluations()
                .into_iter()
                .map(|val| abbreviate_field_value(&format!("{}", val)))
                .collect(),
        );

        if let Some(activator_poly) = &activator {
            headers.push(format!("{base_name} (activator)"));
            columns.push(
                activator_poly
                    .evaluations()
                    .into_iter()
                    .map(|val| abbreviate_field_value(&format!("{}", val)))
                    .collect(),
            );
        }

        if headers.is_empty() {
            return "TrackedCol<empty>".to_string();
        }

        let num_rows = columns.first().map(|col| col.len()).unwrap_or(0);
        let row_numbers = (0..num_rows).map(|idx| idx.to_string()).collect::<Vec<_>>();
        headers.insert(0, "row# (display)".to_string());
        columns.insert(0, row_numbers);

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

impl<B: SnarkBackend> DeepClone<B> for TrackedCol<B> {
    fn deep_clone(&self, new_prover: ArgProver<B>) -> Self {
        match self {
            Self::SingleSegment {
                poly_bundle,
                field_ref,
            } => Self::SingleSegment {
                poly_bundle: PolyBundle {
                    data: poly_bundle.data.deep_clone(new_prover.clone()),
                    activator: poly_bundle
                        .activator
                        .as_ref()
                        .map(|activator| activator.deep_clone(new_prover)),
                },
                field_ref: field_ref.clone(),
            },
            Self::MultiSegment {
                primary_poly_bundle,
                aux_poly_bundles,
                field_ref,
            } => Self::MultiSegment {
                primary_poly_bundle: PolyBundle {
                    data: primary_poly_bundle.data.deep_clone(new_prover.clone()),
                    activator: primary_poly_bundle
                        .activator
                        .as_ref()
                        .map(|act| act.deep_clone(new_prover.clone())),
                },
                aux_poly_bundles: aux_poly_bundles
                    .iter()
                    .map(|(sid, aux)| {
                        (
                            sid.clone(),
                            PolyBundle {
                                data: aux.data.deep_clone(new_prover.clone()),
                                activator: aux
                                    .activator
                                    .as_ref()
                                    .map(|a| a.deep_clone(new_prover.clone())),
                            },
                        )
                    })
                    .collect(),
                field_ref: field_ref.clone(),
            },
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
