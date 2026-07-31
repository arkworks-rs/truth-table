use ark_piop::SnarkBackend;
use ark_piop::verifier::{ArgVerifier, structs::oracle::TrackedOracle};
use datafusion::arrow::datatypes::FieldRef;
use derivative::Derivative;
use indexmap::IndexMap;

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
        /// The primary (canonical) data oracle. Always present.
        primary_data_tracked_oracle: TrackedOracle<B>,
        /// Activator paired with the primary data oracle.
        primary_activator_tracked_oracle: Option<TrackedOracle<B>>,
        /// Non-primary ("auxiliary") data oracles.
        aux_data_tracked_oracles: Vec<TrackedOracle<B>>,
        /// Distinct activator groups among aux segments only.
        aux_activator_tracked_oracles: Vec<Option<TrackedOracle<B>>>,
        /// `aux_segment_id → (aux_data_idx, aux_activator_idx)`. Empty ids
        /// are rejected — primary is not in this map.
        aux_segment_map: IndexMap<String, (usize, usize)>,
        /// Side-domain segments owned by this column oracle (verifier
        /// mirror of `TrackedCol::MultiSegment.side_tracked_polys`). Keyed
        /// by segment suffix.
        side_tracked_oracles: IndexMap<String, crate::table_oracle::TrackedSideColOracle<B>>,
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
                aux_data_tracked_oracles,
                aux_activator_tracked_oracles,
                aux_segment_map,
                side_tracked_oracles,
                field_ref,
                ..
            } => f
                .debug_struct("TrackedColOracle::MultiSegment")
                .field("num_segments", &(1 + aux_data_tracked_oracles.len()))
                .field(
                    "num_aux_activator_groups",
                    &aux_activator_tracked_oracles.len(),
                )
                .field("aux_segments", &aux_segment_map.keys().collect::<Vec<_>>())
                .field(
                    "side_segments",
                    &side_tracked_oracles.keys().collect::<Vec<_>>(),
                )
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

    /// Constructs a multi-segment tracked column oracle: one required
    /// primary segment plus zero or more named aux segments plus zero or
    /// more named side-domain segments. Aux ids must be non-empty (the
    /// primary owns the empty id by convention). Aux activators are
    /// deduplicated by equality to form activator groups. Side segments
    /// live on their own multilinear domain and are keyed by suffix.
    pub fn new_multi(
        primary_data_tracked_oracle: TrackedOracle<B>,
        primary_activator_tracked_oracle: Option<TrackedOracle<B>>,
        aux_segments: Vec<(String, TrackedOracle<B>, Option<TrackedOracle<B>>)>,
        side_segments: Vec<(String, crate::table_oracle::TrackedSideColOracle<B>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let mut aux_data_tracked_oracles: Vec<TrackedOracle<B>> =
            Vec::with_capacity(aux_segments.len());
        let mut aux_activator_tracked_oracles: Vec<Option<TrackedOracle<B>>> = Vec::new();
        let mut aux_segment_map: IndexMap<String, (usize, usize)> =
            IndexMap::with_capacity(aux_segments.len());
        for (sid, data_oracle, activator_oracle) in aux_segments {
            assert!(
                !sid.is_empty(),
                "MultiSegment aux segment id must be non-empty (primary owns the empty id)"
            );
            assert!(
                !aux_segment_map.contains_key(&sid),
                "duplicate aux segment id '{sid}' in MultiSegment column oracle"
            );
            let activator_idx = match aux_activator_tracked_oracles.iter().position(|existing| {
                activators_equal(existing.as_ref(), activator_oracle.as_ref())
            }) {
                Some(idx) => idx,
                None => {
                    aux_activator_tracked_oracles.push(activator_oracle.clone());
                    aux_activator_tracked_oracles.len() - 1
                }
            };
            let data_idx = aux_data_tracked_oracles.len();
            aux_data_tracked_oracles.push(data_oracle);
            aux_segment_map.insert(sid, (data_idx, activator_idx));
        }
        let mut side_tracked_oracles: IndexMap<
            String,
            crate::table_oracle::TrackedSideColOracle<B>,
        > = IndexMap::with_capacity(side_segments.len());
        for (sid, side) in side_segments {
            assert!(
                !sid.is_empty(),
                "MultiSegment side segment id must be non-empty"
            );
            assert!(
                !side_tracked_oracles.contains_key(&sid),
                "duplicate side segment id '{sid}' in MultiSegment column oracle"
            );
            side_tracked_oracles.insert(sid, side);
        }
        Self::MultiSegment {
            primary_data_tracked_oracle,
            primary_activator_tracked_oracle,
            aux_data_tracked_oracles,
            aux_activator_tracked_oracles,
            aux_segment_map,
            side_tracked_oracles,
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

    /// Number of data oracles (segments) in this column. Always >= 1.
    pub fn num_segments(&self) -> usize {
        match self {
            Self::SingleSegment { .. } => 1,
            Self::MultiSegment {
                aux_data_tracked_oracles,
                ..
            } => 1 + aux_data_tracked_oracles.len(),
        }
    }

    /// Iterate `(id, data_oracle, activator_oracle)` over every segment.
    /// Primary yields `id = None`; aux segments yield `id = Some(sid)` in
    /// insertion order. For SingleSegment, only the primary is yielded.
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
                aux_data_tracked_oracles,
                aux_activator_tracked_oracles,
                aux_segment_map,
                ..
            } => {
                let primary = std::iter::once((
                    None,
                    primary_data_tracked_oracle,
                    primary_activator_tracked_oracle.as_ref(),
                ));
                let aux = aux_segment_map.iter().map(move |(sid, (data_idx, act_idx))| {
                    (
                        Some(sid.as_str()),
                        &aux_data_tracked_oracles[*data_idx],
                        aux_activator_tracked_oracles[*act_idx].as_ref(),
                    )
                });
                Box::new(primary.chain(aux))
            }
        }
    }

    /// Look up an aux segment by id. Returns `None` if the id is not a
    /// registered aux (including if this is a `SingleSegment` oracle).
    /// Use `data_tracked_oracle()` / `activator_tracked_oracle()` to reach
    /// the primary.
    pub fn aux_segment(
        &self,
        aux_id: &str,
    ) -> Option<(TrackedOracle<B>, Option<TrackedOracle<B>>)> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                aux_data_tracked_oracles,
                aux_activator_tracked_oracles,
                aux_segment_map,
                ..
            } => aux_segment_map.get(aux_id).map(|(data_idx, act_idx)| {
                (
                    aux_data_tracked_oracles[*data_idx].clone(),
                    aux_activator_tracked_oracles[*act_idx].clone(),
                )
            }),
        }
    }

    /// Look up a side-domain segment by suffix. Returns `None` for
    /// `SingleSegment` oracles or when the suffix is not registered.
    pub fn side_segment(
        &self,
        side_id: &str,
    ) -> Option<&crate::table_oracle::TrackedSideColOracle<B>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                side_tracked_oracles,
                ..
            } => side_tracked_oracles.get(side_id),
        }
    }

    /// Iterate `(suffix, side_oracle)` over every side-domain segment in
    /// this column oracle, in insertion order. Empty for `SingleSegment`.
    pub fn side_segments_iter(
        &self,
    ) -> Box<
        dyn Iterator<Item = (&str, &crate::table_oracle::TrackedSideColOracle<B>)> + '_,
    > {
        match self {
            Self::SingleSegment { .. } => Box::new(std::iter::empty()),
            Self::MultiSegment {
                side_tracked_oracles,
                ..
            } => Box::new(
                side_tracked_oracles
                    .iter()
                    .map(|(sid, side)| (sid.as_str(), side)),
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
