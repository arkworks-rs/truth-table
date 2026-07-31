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

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// An abstraction of a tracked arithmetized column in dbSNARK.
///
/// Most columns are `SingleSegment` (one data polynomial + an optional
/// activator). String-like columns (and any future multi-aspect encoding)
/// expand into `MultiSegment`, which carries multiple data polynomials
/// that all describe the same logical column (e.g. hash + length). Each
/// data polynomial belongs to an activator group; segments in the same
/// group share an activator polynomial, segments in different groups
/// have independent activators.
pub enum TrackedCol<B: SnarkBackend> {
    SingleSegment {
        data_tracked_poly: TrackedPoly<B>,
        activator_tracked_poly: Option<TrackedPoly<B>>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        /// The primary (canonical) data polynomial. Always present.
        primary_data_tracked_poly: TrackedPoly<B>,
        /// Activator paired with the primary data polynomial.
        primary_activator_tracked_poly: Option<TrackedPoly<B>>,
        /// Non-primary ("auxiliary") data polynomials — e.g. `__length`,
        /// `__chars` for a string encoding.
        aux_data_tracked_polys: Vec<TrackedPoly<B>>,
        /// Distinct activator groups among aux segments only. Auxes that
        /// share an activator share the same index; auxes that share
        /// primary's activator store their own reference (compared by
        /// `TrackedPoly` equality downstream).
        aux_activator_tracked_polys: Vec<Option<TrackedPoly<B>>>,
        /// `aux_segment_id → (aux_data_idx, aux_activator_idx)`. Empty ids
        /// are rejected — primary is not in this map.
        aux_segment_map: IndexMap<String, (usize, usize)>,
        field_ref: Option<FieldRef>,
    },
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedCol<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SingleSegment {
                data_tracked_poly,
                activator_tracked_poly,
                field_ref,
            } => f
                .debug_struct("TrackedCol::SingleSegment")
                .field("log_size", &data_tracked_poly.log_size())
                .field("has_activator", &activator_tracked_poly.is_some())
                .field("field_ref", field_ref)
                .finish(),
            Self::MultiSegment {
                aux_data_tracked_polys,
                aux_activator_tracked_polys,
                aux_segment_map,
                field_ref,
                ..
            } => f
                .debug_struct("TrackedCol::MultiSegment")
                .field("num_segments", &(1 + aux_data_tracked_polys.len()))
                .field(
                    "num_aux_activator_groups",
                    &aux_activator_tracked_polys.len(),
                )
                .field("aux_segments", &aux_segment_map.keys().collect::<Vec<_>>())
                .field("field_ref", field_ref)
                .finish(),
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
            Self::SingleSegment {
                data_tracked_poly,
                activator_tracked_poly,
                ..
            } => write!(
                f,
                "{}: data={}, activator={}",
                field_name,
                data_repr(data_tracked_poly),
                activator_repr(activator_tracked_poly),
            ),
            Self::MultiSegment {
                primary_data_tracked_poly,
                primary_activator_tracked_poly,
                aux_data_tracked_polys,
                aux_activator_tracked_polys,
                aux_segment_map,
                ..
            } => {
                writeln!(f, "{} (multi-segment):", field_name)?;
                writeln!(
                    f,
                    "  <primary>: data={}, activator={}",
                    data_repr(primary_data_tracked_poly),
                    activator_repr(primary_activator_tracked_poly),
                )?;
                for (sid, (data_idx, activator_idx)) in aux_segment_map.iter() {
                    writeln!(
                        f,
                        "  {}: data={}, activator={}",
                        sid,
                        data_repr(&aux_data_tracked_polys[*data_idx]),
                        activator_repr(&aux_activator_tracked_polys[*activator_idx]),
                    )?;
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
            data_tracked_poly,
            activator_tracked_poly,
            field_ref,
        }
    }

    /// Constructs a multi-segment tracked column: one required primary
    /// segment plus zero or more named aux segments. Aux ids must be
    /// non-empty (the primary owns the empty id by convention). Aux
    /// segments that share the same activator share an activator group
    /// (compared by `TrackedPoly` equality).
    pub fn new_multi(
        primary_data_tracked_poly: TrackedPoly<B>,
        primary_activator_tracked_poly: Option<TrackedPoly<B>>,
        aux_segments: Vec<(String, TrackedPoly<B>, Option<TrackedPoly<B>>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let mut aux_data_tracked_polys: Vec<TrackedPoly<B>> =
            Vec::with_capacity(aux_segments.len());
        let mut aux_activator_tracked_polys: Vec<Option<TrackedPoly<B>>> = Vec::new();
        let mut aux_segment_map: IndexMap<String, (usize, usize)> =
            IndexMap::with_capacity(aux_segments.len());
        for (sid, data_poly, activator_poly) in aux_segments {
            assert!(
                !sid.is_empty(),
                "MultiSegment aux segment id must be non-empty (primary owns the empty id)"
            );
            assert!(
                !aux_segment_map.contains_key(&sid),
                "duplicate aux segment id '{sid}' in MultiSegment column"
            );
            let activator_idx = match aux_activator_tracked_polys
                .iter()
                .position(|existing| activators_equal(existing.as_ref(), activator_poly.as_ref()))
            {
                Some(idx) => idx,
                None => {
                    aux_activator_tracked_polys.push(activator_poly.clone());
                    aux_activator_tracked_polys.len() - 1
                }
            };
            let data_idx = aux_data_tracked_polys.len();
            aux_data_tracked_polys.push(data_poly);
            aux_segment_map.insert(sid, (data_idx, activator_idx));
        }
        Self::MultiSegment {
            primary_data_tracked_poly,
            primary_activator_tracked_poly,
            aux_data_tracked_polys,
            aux_activator_tracked_polys,
            aux_segment_map,
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

    /// Returns the log size of the tracked polynomials. All segments in a
    /// multi-segment column share the same log size by construction.
    pub fn log_size(&self) -> usize {
        match self {
            Self::SingleSegment {
                data_tracked_poly, ..
            } => data_tracked_poly.log_size(),
            Self::MultiSegment {
                primary_data_tracked_poly,
                ..
            } => primary_data_tracked_poly.log_size(),
        }
    }

    /// Returns the primary data polynomial — the unique poly for a single-
    /// segment column, or the primary of a multi-segment column.
    pub fn data_tracked_poly(&self) -> TrackedPoly<B> {
        match self {
            Self::SingleSegment {
                data_tracked_poly, ..
            } => data_tracked_poly.clone(),
            Self::MultiSegment {
                primary_data_tracked_poly,
                ..
            } => primary_data_tracked_poly.clone(),
        }
    }

    /// Returns the activator polynomial paired with the primary data segment.
    pub fn activator_tracked_poly(&self) -> Option<TrackedPoly<B>> {
        match self {
            Self::SingleSegment {
                activator_tracked_poly,
                ..
            } => activator_tracked_poly.clone(),
            Self::MultiSegment {
                primary_activator_tracked_poly,
                ..
            } => primary_activator_tracked_poly.clone(),
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

    /// Number of data polynomials (segments) in this column. Always >= 1.
    pub fn num_segments(&self) -> usize {
        match self {
            Self::SingleSegment { .. } => 1,
            Self::MultiSegment {
                aux_data_tracked_polys,
                ..
            } => 1 + aux_data_tracked_polys.len(),
        }
    }

    /// Iterate `(id, data_poly, activator_poly)` over every segment in this
    /// column. Primary yields `id = None`; aux segments yield `id = Some(sid)`
    /// in insertion order. For SingleSegment, only the primary is yielded.
    pub fn segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (Option<&str>, &TrackedPoly<B>, Option<&TrackedPoly<B>>)> + '_>
    {
        match self {
            Self::SingleSegment {
                data_tracked_poly,
                activator_tracked_poly,
                ..
            } => Box::new(std::iter::once((
                None,
                data_tracked_poly,
                activator_tracked_poly.as_ref(),
            ))),
            Self::MultiSegment {
                primary_data_tracked_poly,
                primary_activator_tracked_poly,
                aux_data_tracked_polys,
                aux_activator_tracked_polys,
                aux_segment_map,
                ..
            } => {
                let primary = std::iter::once((
                    None,
                    primary_data_tracked_poly,
                    primary_activator_tracked_poly.as_ref(),
                ));
                let aux = aux_segment_map.iter().map(move |(sid, (data_idx, act_idx))| {
                    (
                        Some(sid.as_str()),
                        &aux_data_tracked_polys[*data_idx],
                        aux_activator_tracked_polys[*act_idx].as_ref(),
                    )
                });
                Box::new(primary.chain(aux))
            }
        }
    }

    /// Look up an aux segment by id. Returns `None` if the id is not a
    /// registered aux (including if this is a `SingleSegment` column, which
    /// has no aux). Use `data_tracked_poly()` / `activator_tracked_poly()`
    /// to reach the primary.
    pub fn aux_segment(
        &self,
        aux_id: &str,
    ) -> Option<(TrackedPoly<B>, Option<TrackedPoly<B>>)> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                aux_data_tracked_polys,
                aux_activator_tracked_polys,
                aux_segment_map,
                ..
            } => aux_segment_map.get(aux_id).map(|(data_idx, act_idx)| {
                (
                    aux_data_tracked_polys[*data_idx].clone(),
                    aux_activator_tracked_polys[*act_idx].clone(),
                )
            }),
        }
    }

    /// Returns a reference to the tracker shared by all polys in this column.
    pub fn tracker_ref(&self) -> ArgProver<B> {
        let poly = match self {
            Self::SingleSegment {
                data_tracked_poly, ..
            } => data_tracked_poly,
            Self::MultiSegment {
                primary_data_tracked_poly,
                ..
            } => primary_data_tracked_poly,
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
                data_tracked_poly,
                activator_tracked_poly,
                field_ref,
            } => Self::SingleSegment {
                data_tracked_poly: data_tracked_poly.deep_clone(new_prover.clone()),
                activator_tracked_poly: activator_tracked_poly
                    .as_ref()
                    .map(|activator| activator.deep_clone(new_prover)),
                field_ref: field_ref.clone(),
            },
            Self::MultiSegment {
                primary_data_tracked_poly,
                primary_activator_tracked_poly,
                aux_data_tracked_polys,
                aux_activator_tracked_polys,
                aux_segment_map,
                field_ref,
            } => Self::MultiSegment {
                primary_data_tracked_poly: primary_data_tracked_poly
                    .deep_clone(new_prover.clone()),
                primary_activator_tracked_poly: primary_activator_tracked_poly
                    .as_ref()
                    .map(|act| act.deep_clone(new_prover.clone())),
                aux_data_tracked_polys: aux_data_tracked_polys
                    .iter()
                    .map(|poly| poly.deep_clone(new_prover.clone()))
                    .collect(),
                aux_activator_tracked_polys: aux_activator_tracked_polys
                    .iter()
                    .map(|opt| opt.as_ref().map(|act| act.deep_clone(new_prover.clone())))
                    .collect(),
                aux_segment_map: aux_segment_map.clone(),
                field_ref: field_ref.clone(),
            },
        }
    }
}

fn activators_equal<B: SnarkBackend>(
    lhs: Option<&TrackedPoly<B>>,
    rhs: Option<&TrackedPoly<B>>,
) -> bool {
    match (lhs, rhs) {
        (None, None) => true,
        (Some(a), Some(b)) => a == b,
        _ => false,
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
