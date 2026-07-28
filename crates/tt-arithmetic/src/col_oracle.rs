use ark_piop::SnarkBackend;
use ark_piop::verifier::{ArgVerifier, structs::oracle::TrackedOracle};
use datafusion::arrow::datatypes::FieldRef;
use derivative::Derivative;
use indexmap::IndexMap;

use crate::col::PRIMARY_SEGMENT_ID;

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// Verifier-side mirror of `TrackedCol`. Single-segment columns carry one
/// oracle; multi-segment columns carry several oracles per logical column,
/// grouped by activator (segments sharing an activator group share an index
/// into `activator_tracked_oracles`).
pub enum TrackedColOracle<B: SnarkBackend> {
    SingleSegment {
        data_tracked_oracle: TrackedOracle<B>,
        activator_tracked_oracle: Option<TrackedOracle<B>>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        data_tracked_oracles: Vec<TrackedOracle<B>>,
        activator_tracked_oracles: Vec<Option<TrackedOracle<B>>>,
        /// `segment_id → (data_idx, activator_idx)`.
        segment_map: IndexMap<String, (usize, usize)>,
        field_ref: Option<FieldRef>,
    },
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedColOracle<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SingleSegment {
                data_tracked_oracle,
                activator_tracked_oracle,
                field_ref,
            } => f
                .debug_struct("TrackedColOracle::SingleSegment")
                .field("log_size", &data_tracked_oracle.log_size())
                .field("has_activator", &activator_tracked_oracle.is_some())
                .field("field_ref", field_ref)
                .finish(),
            Self::MultiSegment {
                data_tracked_oracles,
                activator_tracked_oracles,
                segment_map,
                field_ref,
            } => f
                .debug_struct("TrackedColOracle::MultiSegment")
                .field("num_segments", &data_tracked_oracles.len())
                .field("num_activator_groups", &activator_tracked_oracles.len())
                .field("segments", &segment_map.keys().collect::<Vec<_>>())
                .field("field_ref", field_ref)
                .finish(),
        }
    }
}

impl<B: SnarkBackend> TrackedColOracle<B> {
    /// Constructs a single-segment tracked column oracle.
    pub fn new(
        data_tracked_oracle: TrackedOracle<B>,
        activator_tracked_oracle: Option<TrackedOracle<B>>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&data_tracked_oracle, &activator_tracked_oracle, &field_ref);
        }
        Self::SingleSegment {
            data_tracked_oracle,
            activator_tracked_oracle,
            field_ref,
        }
    }

    /// Constructs a multi-segment tracked column oracle, deduplicating
    /// activator oracles by equality to form activator groups.
    pub fn new_multi(
        segments: Vec<(String, TrackedOracle<B>, Option<TrackedOracle<B>>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        assert!(
            !segments.is_empty(),
            "MultiSegment column oracle requires at least one segment"
        );
        let mut data_tracked_oracles: Vec<TrackedOracle<B>> = Vec::with_capacity(segments.len());
        let mut activator_tracked_oracles: Vec<Option<TrackedOracle<B>>> = Vec::new();
        let mut segment_map: IndexMap<String, (usize, usize)> =
            IndexMap::with_capacity(segments.len());
        for (sid, data_oracle, activator_oracle) in segments {
            let activator_idx = match activator_tracked_oracles.iter().position(|existing| {
                activators_equal(existing.as_ref(), activator_oracle.as_ref())
            }) {
                Some(idx) => idx,
                None => {
                    activator_tracked_oracles.push(activator_oracle.clone());
                    activator_tracked_oracles.len() - 1
                }
            };
            let data_idx = data_tracked_oracles.len();
            data_tracked_oracles.push(data_oracle);
            segment_map.insert(sid, (data_idx, activator_idx));
        }
        Self::MultiSegment {
            data_tracked_oracles,
            activator_tracked_oracles,
            segment_map,
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
            // A folded-constant oracle evaluates identically on any hypercube,
            // so its stored log_size is unconstrained. Only enforce the size
            // match when both sides are non-constant. Mirrors
            // `TrackedCol::check_new_args`.
            if !data_tracked_oracle.is_constant() && !activator.is_constant() {
                debug_assert_eq!(data_tracked_oracle.log_size(), activator.log_size());
            }
            debug_assert!(data_tracked_oracle.same_tracker(activator));
        }
    }

    /// Returns the log size of the tracked oracle. Multi-segment oracles
    /// share log size across all segments by construction.
    pub fn log_size(&self) -> usize {
        match self {
            Self::SingleSegment {
                data_tracked_oracle,
                ..
            } => data_tracked_oracle.log_size(),
            Self::MultiSegment {
                data_tracked_oracles,
                ..
            } => data_tracked_oracles[0].log_size(),
        }
    }

    /// Returns the primary data oracle.
    pub fn data_tracked_oracle(&self) -> TrackedOracle<B> {
        match self {
            Self::SingleSegment {
                data_tracked_oracle,
                ..
            } => data_tracked_oracle.clone(),
            Self::MultiSegment {
                data_tracked_oracles,
                segment_map,
                ..
            } => {
                let (data_idx, _) = segment_map
                    .get(PRIMARY_SEGMENT_ID)
                    .or_else(|| segment_map.values().next())
                    .expect("multi-segment column oracle must contain at least one segment");
                data_tracked_oracles[*data_idx].clone()
            }
        }
    }

    /// Returns the primary segment's activator oracle.
    pub fn activator_tracked_oracle(&self) -> Option<TrackedOracle<B>> {
        match self {
            Self::SingleSegment {
                activator_tracked_oracle,
                ..
            } => activator_tracked_oracle.clone(),
            Self::MultiSegment {
                activator_tracked_oracles,
                segment_map,
                ..
            } => {
                let (_, activator_idx) = segment_map
                    .get(PRIMARY_SEGMENT_ID)
                    .or_else(|| segment_map.values().next())
                    .expect("multi-segment column oracle must contain at least one segment");
                activator_tracked_oracles[*activator_idx].clone()
            }
        }
    }

    /// Returns the field reference, if any.
    pub fn field_ref(&self) -> Option<FieldRef> {
        match self {
            Self::SingleSegment { field_ref, .. } | Self::MultiSegment { field_ref, .. } => {
                field_ref.clone()
            }
        }
    }

    /// Number of data oracles (segments) in this column. Always >= 1.
    pub fn num_segments(&self) -> usize {
        match self {
            Self::SingleSegment { .. } => 1,
            Self::MultiSegment {
                data_tracked_oracles,
                ..
            } => data_tracked_oracles.len(),
        }
    }

    /// Iterate `(segment_id, data_oracle, activator_oracle)` over every
    /// segment, in insertion order.
    pub fn segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (&str, &TrackedOracle<B>, Option<&TrackedOracle<B>>)> + '_> {
        match self {
            Self::SingleSegment {
                data_tracked_oracle,
                activator_tracked_oracle,
                ..
            } => Box::new(std::iter::once((
                PRIMARY_SEGMENT_ID,
                data_tracked_oracle,
                activator_tracked_oracle.as_ref(),
            ))),
            Self::MultiSegment {
                data_tracked_oracles,
                activator_tracked_oracles,
                segment_map,
                ..
            } => Box::new(segment_map.iter().map(move |(sid, (data_idx, act_idx))| {
                (
                    sid.as_str(),
                    &data_tracked_oracles[*data_idx],
                    activator_tracked_oracles[*act_idx].as_ref(),
                )
            })),
        }
    }

    /// Look up a specific segment by id.
    pub fn segment(
        &self,
        segment_id: &str,
    ) -> Option<(TrackedOracle<B>, Option<TrackedOracle<B>>)> {
        match self {
            Self::SingleSegment {
                data_tracked_oracle,
                activator_tracked_oracle,
                ..
            } => {
                if segment_id == PRIMARY_SEGMENT_ID {
                    Some((
                        data_tracked_oracle.clone(),
                        activator_tracked_oracle.clone(),
                    ))
                } else {
                    None
                }
            }
            Self::MultiSegment {
                data_tracked_oracles,
                activator_tracked_oracles,
                segment_map,
                ..
            } => segment_map.get(segment_id).map(|(data_idx, act_idx)| {
                (
                    data_tracked_oracles[*data_idx].clone(),
                    activator_tracked_oracles[*act_idx].clone(),
                )
            }),
        }
    }

    /// Returns the verifier tracker.
    pub fn tracker_ref(&self) -> ArgVerifier<B> {
        let oracle = match self {
            Self::SingleSegment {
                data_tracked_oracle,
                ..
            } => data_tracked_oracle,
            Self::MultiSegment {
                data_tracked_oracles,
                ..
            } => &data_tracked_oracles[0],
        };
        ArgVerifier::new_from_tracker_rc(oracle.tracker().clone())
    }

    /// Returns the primary data oracle multiplied by its activator
    /// (when one exists).
    pub fn activated_data_tracked_oracle(&self) -> TrackedOracle<B> {
        match self.activator_tracked_oracle() {
            Some(activator) => &self.data_tracked_oracle() * &activator,
            None => self.data_tracked_oracle(),
        }
    }

    /// Pretty-print column oracle headers (primary segment only).
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

        let mut headers = Vec::with_capacity(2);
        headers.push(base_name.clone());

        if self.activator_tracked_oracle().is_some() {
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

fn activators_equal<B: SnarkBackend>(
    lhs: Option<&TrackedOracle<B>>,
    rhs: Option<&TrackedOracle<B>>,
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
