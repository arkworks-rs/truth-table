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

/// One polynomial of a tracked column with the activator paired with it.
///
/// - A row-domain aux segment (`__length`) has the primary's activator,
///   which is `None` on a base table without a filter.
/// - A side-domain segment (`__chars`, `__orig_ind`) always has its own
///   contiguous-one activator over the side domain.
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""), Debug(bound = ""))]
pub struct PolyBundle<B: SnarkBackend> {
    pub data: TrackedPoly<B>,
    pub activator: Option<TrackedPoly<B>>,
}

impl<B: SnarkBackend> PolyBundle<B> {
    pub fn new(data: TrackedPoly<B>, activator: Option<TrackedPoly<B>>) -> Self {
        Self { data, activator }
    }

    pub fn log_size(&self) -> usize {
        self.data.log_size()
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// A tracked arithmetized column.
///
/// Most columns are `SingleSegment`: one data polynomial and an optional
/// activator. A multi-segment encoding (a string) is `MultiSegment`: a
/// primary polynomial plus auxiliary ones, keyed by segment suffix.
///
/// Which auxiliary segments are side-domain is stored in
/// `side_aux_suffixes`, not derived from `log_size`: a side domain can be
/// padded to the same size as the row domain (the characters of a column
/// of one-character strings), and a side segment taken for a row segment
/// would show up in `segments_iter`.
pub enum TrackedCol<B: SnarkBackend> {
    SingleSegment {
        poly_bundle: PolyBundle<B>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        primary_poly_bundle: PolyBundle<B>,
        /// Row-domain and side-domain auxiliary segments, keyed by suffix
        /// (`__length`, `__chars`, `__orig_ind`, `__bnd`).
        aux_poly_bundles: IndexMap<String, PolyBundle<B>>,
        /// The keys of `aux_poly_bundles` that are side-domain.
        side_aux_suffixes: IndexSet<String>,
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
                primary_poly_bundle: _,
                aux_poly_bundles,
                side_aux_suffixes,
                field_ref,
            } => {
                let (side_ids, row_ids): (Vec<_>, Vec<_>) = aux_poly_bundles
                    .iter()
                    .partition(|(sid, _)| side_aux_suffixes.contains(sid.as_str()));
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
                side_aux_suffixes,
                ..
            } => {
                writeln!(f, "{} (multi-segment):", field_name)?;
                writeln!(
                    f,
                    "  <primary>: data={}, activator={}",
                    data_repr(&primary_poly_bundle.data),
                    activator_repr(&primary_poly_bundle.activator),
                )?;
                for (sid, aux) in aux_poly_bundles.iter() {
                    if side_aux_suffixes.contains(sid.as_str()) {
                        writeln!(f, "  {} (side): log_size={}", sid, aux.log_size(),)?;
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
    /// A single-segment column.
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

    /// [`Self::new_multi_split`] for a merged aux list: an aux segment is
    /// taken as side-domain iff its `log_size` differs from the primary's.
    /// That misclassifies a side segment whose domain has the primary's
    /// size (see the enum doc), so use `new_multi_split` when the split is
    /// known.
    pub fn new_multi(
        primary_poly_bundle: PolyBundle<B>,
        aux_poly_bundles_input: Vec<(String, PolyBundle<B>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let primary_log_size = primary_poly_bundle.log_size();
        let mut row_aux: Vec<(String, PolyBundle<B>)> = Vec::new();
        let mut side_aux: Vec<(String, PolyBundle<B>)> = Vec::new();
        for (sid, aux) in aux_poly_bundles_input {
            if aux.log_size() == primary_log_size {
                row_aux.push((sid, aux));
            } else {
                side_aux.push((sid, aux));
            }
        }
        Self::new_multi_split(primary_poly_bundle, row_aux, side_aux, field_ref)
    }

    /// A multi-segment column from its primary bundle and its row-domain
    /// and side-domain aux bundles. Aux ids must be non-empty (the primary
    /// owns the empty id) and distinct.
    pub fn new_multi_split(
        primary_poly_bundle: PolyBundle<B>,
        row_aux_input: Vec<(String, PolyBundle<B>)>,
        side_aux_input: Vec<(String, PolyBundle<B>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let mut aux_poly_bundles: IndexMap<String, PolyBundle<B>> =
            IndexMap::with_capacity(row_aux_input.len() + side_aux_input.len());
        let mut side_aux_suffixes: IndexSet<String> = IndexSet::with_capacity(side_aux_input.len());
        for (sid, aux) in row_aux_input {
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
        for (sid, aux) in side_aux_input {
            assert!(
                !sid.is_empty(),
                "MultiSegment aux segment id must be non-empty (primary owns the empty id)"
            );
            assert!(
                !aux_poly_bundles.contains_key(&sid),
                "duplicate aux segment id '{sid}' in MultiSegment column"
            );
            aux_poly_bundles.insert(sid.clone(), aux);
            side_aux_suffixes.insert(sid);
        }
        Self::MultiSegment {
            primary_poly_bundle,
            aux_poly_bundles,
            side_aux_suffixes,
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
            // so its stored log_size is unconstrained: the sizes must match
            // only when both sides are non-constant.
            if !data_tracked_poly.is_constant() && !activator.is_constant() {
                debug_assert_eq!(data_tracked_poly.log_size(), activator.log_size());
            }
            debug_assert!(data_tracked_poly.same_tracker(activator));
        }
    }

    /// The log size of the row domain, which all row-domain segments share.
    pub fn log_size(&self) -> usize {
        match self {
            Self::SingleSegment { poly_bundle, .. } => poly_bundle.log_size(),
            Self::MultiSegment {
                primary_poly_bundle,
                ..
            } => primary_poly_bundle.log_size(),
        }
    }

    /// The primary data polynomial.
    pub fn data_tracked_poly(&self) -> TrackedPoly<B> {
        match self {
            Self::SingleSegment { poly_bundle, .. } => poly_bundle.data.clone(),
            Self::MultiSegment {
                primary_poly_bundle,
                ..
            } => primary_poly_bundle.data.clone(),
        }
    }

    /// The activator of the primary data polynomial.
    pub fn activator_tracked_poly(&self) -> Option<TrackedPoly<B>> {
        match self {
            Self::SingleSegment { poly_bundle, .. } => poly_bundle.activator.clone(),
            Self::MultiSegment {
                primary_poly_bundle,
                ..
            } => primary_poly_bundle.activator.clone(),
        }
    }

    pub fn field_ref(&self) -> Option<FieldRef> {
        match self {
            Self::SingleSegment { field_ref, .. } | Self::MultiSegment { field_ref, .. } => {
                field_ref.clone()
            }
        }
    }

    /// The primary plus every aux segment, row-domain and side-domain.
    pub fn num_segments(&self) -> usize {
        match self {
            Self::SingleSegment { .. } => 1,
            Self::MultiSegment {
                aux_poly_bundles, ..
            } => 1 + aux_poly_bundles.len(),
        }
    }

    /// `(id, data, activator)` of the row-domain segments only: the primary
    /// with `id = None`, then each row-domain aux with `id = Some(suffix)`.
    #[allow(clippy::type_complexity)]
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
                side_aux_suffixes,
                ..
            } => {
                let primary = std::iter::once((
                    None,
                    &primary_poly_bundle.data,
                    primary_poly_bundle.activator.as_ref(),
                ));
                let aux = aux_poly_bundles
                    .iter()
                    .filter(move |(sid, _)| !side_aux_suffixes.contains(sid.as_str()))
                    .map(|(sid, aux)| (Some(sid.as_str()), &aux.data, aux.activator.as_ref()));
                Box::new(primary.chain(aux))
            }
        }
    }

    /// The aux segment `aux_id`, row-domain or side-domain.
    pub fn aux_segment(&self, aux_id: &str) -> Option<&PolyBundle<B>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                aux_poly_bundles, ..
            } => aux_poly_bundles.get(aux_id),
        }
    }

    /// The side-domain segment `side_id`; `None` for a row-domain aux.
    pub fn side_segment(&self, side_id: &str) -> Option<&PolyBundle<B>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                aux_poly_bundles,
                side_aux_suffixes,
                ..
            } => {
                if side_aux_suffixes.contains(side_id) {
                    aux_poly_bundles.get(side_id)
                } else {
                    None
                }
            }
        }
    }

    /// `(suffix, aux)` of every side-domain segment, in insertion order.
    pub fn side_segments_iter(&self) -> Box<dyn Iterator<Item = (&str, &PolyBundle<B>)> + '_> {
        match self {
            Self::SingleSegment { .. } => Box::new(std::iter::empty()),
            Self::MultiSegment {
                aux_poly_bundles,
                side_aux_suffixes,
                ..
            } => Box::new(
                aux_poly_bundles
                    .iter()
                    .filter(move |(sid, _)| side_aux_suffixes.contains(sid.as_str()))
                    .map(|(sid, aux)| (sid.as_str(), aux)),
            ),
        }
    }

    /// The tracker shared by all polynomials of this column.
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

    /// The primary data polynomial times its activator, when it has one.
    pub fn activated_data_tracked_poly(&self) -> TrackedPoly<B> {
        match self.activator_tracked_poly() {
            Some(activator) => &self.data_tracked_poly() * &activator,
            None => self.data_tracked_poly(),
        }
    }

    /// The primary data values of the active rows.
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

    /// The distinct primary data values of the active rows.
    pub fn effective_hashset(&self) -> IndexSet<B::F> {
        self.effective_iter()
            .into_iter()
            .collect::<IndexSet<B::F>>()
    }

    /// A text table of the primary segment and its activator.
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
                side_aux_suffixes,
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
                side_aux_suffixes: side_aux_suffixes.clone(),
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
