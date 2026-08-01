use ark_piop::SnarkBackend;
use ark_piop::verifier::{ArgVerifier, structs::oracle::TrackedOracle};
use datafusion::arrow::datatypes::FieldRef;
use derivative::Derivative;
use indexmap::IndexMap;

/// Verifier-side mirror of `TrackedAuxPoly`. Uniform payload for both
/// row-domain aux oracles and side-domain aux oracles; distinguished by
/// `active_len` (Some → contiguous-one activator, i.e. side-domain).
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""), Debug(bound = ""))]
pub struct TrackedAuxOracle<B: SnarkBackend> {
    pub data: TrackedOracle<B>,
    pub activator: Option<TrackedOracle<B>>,
    pub active_len: Option<usize>,
}

impl<B: SnarkBackend> TrackedAuxOracle<B> {
    pub fn new_row(data: TrackedOracle<B>, activator: Option<TrackedOracle<B>>) -> Self {
        Self {
            data,
            activator,
            active_len: None,
        }
    }

    pub fn new_side(data: TrackedOracle<B>, activator: TrackedOracle<B>, active_len: usize) -> Self {
        Self {
            data,
            activator: Some(activator),
            active_len: Some(active_len),
        }
    }

    pub fn is_side(&self) -> bool {
        self.active_len.is_some()
    }

    pub fn log_size(&self) -> usize {
        self.data.log_size()
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// Verifier-side mirror of `TrackedCol`. Row-domain and side-domain aux
/// oracles live in the same `aux_segments` map; see [`TrackedAuxOracle`].
pub enum TrackedColOracle<B: SnarkBackend> {
    SingleSegment {
        data_tracked_oracle: TrackedOracle<B>,
        activator_tracked_oracle: Option<TrackedOracle<B>>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        /// The primary (canonical) data oracle. Always present.
        primary_data_tracked_oracle: TrackedOracle<B>,
        /// Activator paired with the primary data oracle.
        primary_activator_tracked_oracle: Option<TrackedOracle<B>>,
        /// All auxiliary oracles (row-domain + side-domain), keyed by
        /// segment suffix.
        aux_segments: IndexMap<String, TrackedAuxOracle<B>>,
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
                aux_segments,
                field_ref,
                ..
            } => {
                let (side_ids, row_ids): (Vec<_>, Vec<_>) = aux_segments
                    .iter()
                    .partition(|(_, aux)| aux.is_side());
                f.debug_struct("TrackedColOracle::MultiSegment")
                    .field("num_segments", &(1 + aux_segments.len()))
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

    /// Constructs a multi-segment tracked column oracle: one required
    /// primary oracle plus zero or more named aux oracles. Aux ids must
    /// be non-empty (the primary owns the empty id by convention).
    /// Row- and side-domain aux oracles live in the same map; each
    /// `TrackedAuxOracle` self-describes whether it's a side-domain
    /// segment via `active_len`.
    pub fn new_multi(
        primary_data_tracked_oracle: TrackedOracle<B>,
        primary_activator_tracked_oracle: Option<TrackedOracle<B>>,
        aux_segments_input: Vec<(String, TrackedAuxOracle<B>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let mut aux_segments: IndexMap<String, TrackedAuxOracle<B>> =
            IndexMap::with_capacity(aux_segments_input.len());
        for (sid, aux) in aux_segments_input {
            assert!(
                !sid.is_empty(),
                "MultiSegment aux segment id must be non-empty (primary owns the empty id)"
            );
            assert!(
                !aux_segments.contains_key(&sid),
                "duplicate aux segment id '{sid}' in MultiSegment column oracle"
            );
            aux_segments.insert(sid, aux);
        }
        Self::MultiSegment {
            primary_data_tracked_oracle,
            primary_activator_tracked_oracle,
            aux_segments,
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
                primary_data_tracked_oracle,
                ..
            } => primary_data_tracked_oracle.log_size(),
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
                primary_data_tracked_oracle,
                ..
            } => primary_data_tracked_oracle.clone(),
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
                primary_activator_tracked_oracle,
                ..
            } => primary_activator_tracked_oracle.clone(),
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

    /// Total number of oracles in this column (primary + all aux, row-
    /// domain AND side-domain). Always >= 1.
    pub fn num_segments(&self) -> usize {
        match self {
            Self::SingleSegment { .. } => 1,
            Self::MultiSegment { aux_segments, .. } => 1 + aux_segments.len(),
        }
    }

    /// Iterate `(id, data, activator)` over ROW-domain segments only:
    /// primary yields `id = None`, row-aux yields `id = Some(sid)`.
    /// Side-domain aux excluded — use
    /// [`side_segments_iter`](Self::side_segments_iter).
    pub fn segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (Option<&str>, &TrackedOracle<B>, Option<&TrackedOracle<B>>)> + '_>
    {
        match self {
            Self::SingleSegment {
                data_tracked_oracle,
                activator_tracked_oracle,
                ..
            } => Box::new(std::iter::once((
                None,
                data_tracked_oracle,
                activator_tracked_oracle.as_ref(),
            ))),
            Self::MultiSegment {
                primary_data_tracked_oracle,
                primary_activator_tracked_oracle,
                aux_segments,
                ..
            } => {
                let primary = std::iter::once((
                    None,
                    primary_data_tracked_oracle,
                    primary_activator_tracked_oracle.as_ref(),
                ));
                let aux = aux_segments
                    .iter()
                    .filter(|(_, aux)| !aux.is_side())
                    .map(|(sid, aux)| (Some(sid.as_str()), &aux.data, aux.activator.as_ref()));
                Box::new(primary.chain(aux))
            }
        }
    }

    /// Look up ANY aux segment (row-domain or side-domain) by id.
    /// Returns `None` if the id is not registered (including for
    /// `SingleSegment` oracles).
    pub fn aux_segment(&self, aux_id: &str) -> Option<&TrackedAuxOracle<B>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment { aux_segments, .. } => aux_segments.get(aux_id),
        }
    }

    /// Look up a side-domain segment specifically (returns `None` if the
    /// id resolves to a row-domain aux).
    pub fn side_segment(&self, side_id: &str) -> Option<&TrackedAuxOracle<B>> {
        self.aux_segment(side_id).filter(|aux| aux.is_side())
    }

    /// Iterate `(suffix, aux)` over every side-domain segment in this
    /// column oracle, in insertion order. Empty for `SingleSegment`.
    pub fn side_segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (&str, &TrackedAuxOracle<B>)> + '_> {
        match self {
            Self::SingleSegment { .. } => Box::new(std::iter::empty()),
            Self::MultiSegment { aux_segments, .. } => Box::new(
                aux_segments
                    .iter()
                    .filter(|(_, aux)| aux.is_side())
                    .map(|(sid, aux)| (sid.as_str(), aux)),
            ),
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
                primary_data_tracked_oracle,
                ..
            } => primary_data_tracked_oracle,
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
