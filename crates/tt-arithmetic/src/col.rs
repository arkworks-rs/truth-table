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

/// The conventional id used for a single-segment column or for the "primary"
/// segment of a multi-segment column.
pub const PRIMARY_SEGMENT_ID: &str = "";

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
        /// All data polynomials in this column.
        data_tracked_polys: Vec<TrackedPoly<B>>,
        /// Distinct activator groups within this column. Length = number of
        /// activator groups (often 1; can be > 1 when segments come from
        /// different filter contexts).
        activator_tracked_polys: Vec<Option<TrackedPoly<B>>>,
        /// `segment_id → (data_idx, activator_idx)`. Multiple segments
        /// sharing the same activator share the same `activator_idx`.
        /// The primary segment uses `PRIMARY_SEGMENT_ID` ("").
        segment_map: IndexMap<String, (usize, usize)>,
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
                data_tracked_polys,
                activator_tracked_polys,
                segment_map,
                field_ref,
            } => f
                .debug_struct("TrackedCol::MultiSegment")
                .field("num_segments", &data_tracked_polys.len())
                .field("num_activator_groups", &activator_tracked_polys.len())
                .field("segments", &segment_map.keys().collect::<Vec<_>>())
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
                data_tracked_polys,
                activator_tracked_polys,
                segment_map,
                ..
            } => {
                writeln!(f, "{} (multi-segment):", field_name)?;
                for (sid, (data_idx, activator_idx)) in segment_map.iter() {
                    let label = if sid.is_empty() { "<primary>" } else { sid };
                    writeln!(
                        f,
                        "  {}: data={}, activator={}",
                        label,
                        data_repr(&data_tracked_polys[*data_idx]),
                        activator_repr(&activator_tracked_polys[*activator_idx]),
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

    /// Constructs a multi-segment tracked column from named segments. Each
    /// segment is `(segment_id, data_poly, activator_poly)`; segments that
    /// supply the same activator (compared by identity via `Option<&TrackedPoly>`
    /// equality on the underlying tracker) share an activator group.
    pub fn new_multi(
        segments: Vec<(String, TrackedPoly<B>, Option<TrackedPoly<B>>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        assert!(
            !segments.is_empty(),
            "MultiSegment column requires at least one segment"
        );
        let mut data_tracked_polys: Vec<TrackedPoly<B>> = Vec::with_capacity(segments.len());
        let mut activator_tracked_polys: Vec<Option<TrackedPoly<B>>> = Vec::new();
        let mut segment_map: IndexMap<String, (usize, usize)> =
            IndexMap::with_capacity(segments.len());
        for (sid, data_poly, activator_poly) in segments {
            let activator_idx = match activator_tracked_polys
                .iter()
                .position(|existing| activators_equal(existing.as_ref(), activator_poly.as_ref()))
            {
                Some(idx) => idx,
                None => {
                    activator_tracked_polys.push(activator_poly.clone());
                    activator_tracked_polys.len() - 1
                }
            };
            let data_idx = data_tracked_polys.len();
            data_tracked_polys.push(data_poly);
            segment_map.insert(sid, (data_idx, activator_idx));
        }
        Self::MultiSegment {
            data_tracked_polys,
            activator_tracked_polys,
            segment_map,
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
                data_tracked_polys, ..
            } => data_tracked_polys[0].log_size(),
        }
    }

    /// Returns the primary data polynomial — the unique poly for a single-
    /// segment column, or the poly registered under `PRIMARY_SEGMENT_ID` for
    /// a multi-segment column.
    pub fn data_tracked_poly(&self) -> TrackedPoly<B> {
        match self {
            Self::SingleSegment {
                data_tracked_poly, ..
            } => data_tracked_poly.clone(),
            Self::MultiSegment {
                data_tracked_polys,
                segment_map,
                ..
            } => {
                let (data_idx, _) = segment_map
                    .get(PRIMARY_SEGMENT_ID)
                    .or_else(|| segment_map.values().next())
                    .expect("multi-segment column must contain at least one segment");
                data_tracked_polys[*data_idx].clone()
            }
        }
    }

    /// Returns the activator polynomial paired with the primary data segment.
    /// Single-segment columns return their sole activator. Multi-segment
    /// columns return the activator from the primary segment's group.
    pub fn activator_tracked_poly(&self) -> Option<TrackedPoly<B>> {
        match self {
            Self::SingleSegment {
                activator_tracked_poly,
                ..
            } => activator_tracked_poly.clone(),
            Self::MultiSegment {
                activator_tracked_polys,
                segment_map,
                ..
            } => {
                let (_, activator_idx) = segment_map
                    .get(PRIMARY_SEGMENT_ID)
                    .or_else(|| segment_map.values().next())
                    .expect("multi-segment column must contain at least one segment");
                activator_tracked_polys[*activator_idx].clone()
            }
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
                data_tracked_polys, ..
            } => data_tracked_polys.len(),
        }
    }

    /// Iterate `(segment_id, data_poly, activator_poly)` over every segment
    /// in this column, in insertion order.
    pub fn segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (&str, &TrackedPoly<B>, Option<&TrackedPoly<B>>)> + '_> {
        match self {
            Self::SingleSegment {
                data_tracked_poly,
                activator_tracked_poly,
                ..
            } => Box::new(std::iter::once((
                PRIMARY_SEGMENT_ID,
                data_tracked_poly,
                activator_tracked_poly.as_ref(),
            ))),
            Self::MultiSegment {
                data_tracked_polys,
                activator_tracked_polys,
                segment_map,
                ..
            } => Box::new(segment_map.iter().map(move |(sid, (data_idx, act_idx))| {
                (
                    sid.as_str(),
                    &data_tracked_polys[*data_idx],
                    activator_tracked_polys[*act_idx].as_ref(),
                )
            })),
        }
    }

    /// Look up a specific segment by id. Returns the segment's data and
    /// activator polys.
    pub fn segment(&self, segment_id: &str) -> Option<(TrackedPoly<B>, Option<TrackedPoly<B>>)> {
        match self {
            Self::SingleSegment {
                data_tracked_poly,
                activator_tracked_poly,
                ..
            } => {
                if segment_id == PRIMARY_SEGMENT_ID {
                    Some((data_tracked_poly.clone(), activator_tracked_poly.clone()))
                } else {
                    None
                }
            }
            Self::MultiSegment {
                data_tracked_polys,
                activator_tracked_polys,
                segment_map,
                ..
            } => segment_map.get(segment_id).map(|(data_idx, act_idx)| {
                (
                    data_tracked_polys[*data_idx].clone(),
                    activator_tracked_polys[*act_idx].clone(),
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
                data_tracked_polys, ..
            } => &data_tracked_polys[0],
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
                data_tracked_polys,
                activator_tracked_polys,
                segment_map,
                field_ref,
            } => Self::MultiSegment {
                data_tracked_polys: data_tracked_polys
                    .iter()
                    .map(|poly| poly.deep_clone(new_prover.clone()))
                    .collect(),
                activator_tracked_polys: activator_tracked_polys
                    .iter()
                    .map(|opt| opt.as_ref().map(|act| act.deep_clone(new_prover.clone())))
                    .collect(),
                segment_map: segment_map.clone(),
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
