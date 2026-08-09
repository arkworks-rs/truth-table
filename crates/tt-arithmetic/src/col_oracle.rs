use ark_piop::SnarkBackend;
use ark_piop::verifier::{ArgVerifier, structs::oracle::TrackedOracle};
use datafusion::arrow::datatypes::FieldRef;
use derivative::Derivative;
use indexmap::{IndexMap, IndexSet};

/// Verifier-side mirror of `PolyBundle`: data oracle plus its
/// paired activator (optional — row aux inherit primary's, which may
/// itself be `None` on unfiltered base tables). Row-vs-side is a
/// derived property (compare `data.log_size()` against the owning
/// column's primary log_size).
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""), Debug(bound = ""))]
pub struct OracleBundle<B: SnarkBackend> {
    pub data: TrackedOracle<B>,
    pub activator: Option<TrackedOracle<B>>,
}

impl<B: SnarkBackend> OracleBundle<B> {
    pub fn new(data: TrackedOracle<B>, activator: Option<TrackedOracle<B>>) -> Self {
        Self { data, activator }
    }

    pub fn log_size(&self) -> usize {
        self.data.log_size()
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// Verifier-side mirror of `TrackedCol`. Row-domain and side-domain aux
/// oracles live in the same `aux_segments` map; see [`OracleBundle`].
pub enum TrackedColOracle<B: SnarkBackend> {
    SingleSegment {
        /// The column's data oracle + its (optional) activator.
        oracle_bundle: OracleBundle<B>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        /// The primary (canonical) data oracle + its activator.
        primary_oracle_bundle: OracleBundle<B>,
        /// All auxiliary oracle bundles (row-domain + side-domain),
        /// keyed by segment suffix. Row/side classification lives in
        /// the sibling `side_aux_suffixes` set — see the prover-side
        /// [`crate::col::TrackedCol`] enum docstring for why the
        /// historical `log_size` heuristic was insufficient.
        aux_oracle_bundles: IndexMap<String, OracleBundle<B>>,
        /// Subset of `aux_oracle_bundles` keys that are side-domain.
        side_aux_suffixes: IndexSet<String>,
        field_ref: Option<FieldRef>,
    },
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedColOracle<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SingleSegment {
                oracle_bundle,
                field_ref,
            } => f
                .debug_struct("TrackedColOracle::SingleSegment")
                .field("log_size", &oracle_bundle.log_size())
                .field("has_activator", &oracle_bundle.activator.is_some())
                .field("field_ref", field_ref)
                .finish(),
            Self::MultiSegment {
                primary_oracle_bundle: _,
                aux_oracle_bundles,
                side_aux_suffixes,
                field_ref,
            } => {
                let (side_ids, row_ids): (Vec<_>, Vec<_>) = aux_oracle_bundles
                    .iter()
                    .partition(|(sid, _)| side_aux_suffixes.contains(sid.as_str()));
                f.debug_struct("TrackedColOracle::MultiSegment")
                    .field("num_segments", &(1 + aux_oracle_bundles.len()))
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
            oracle_bundle: OracleBundle::new(data_tracked_oracle, activator_tracked_oracle),
            field_ref,
        }
    }

    /// Constructs a multi-segment tracked column oracle from a MERGED aux
    /// list. Prefer [`Self::new_multi_split`] when the caller has the
    /// row-vs-side split at hand — see the prover-side [`crate::col::TrackedCol::new_multi`]
    /// for the same rationale. This shim auto-classifies each aux by
    /// log_size against the primary; unreliable when the side domain is
    /// pow2-padded to the row size.
    pub fn new_multi(
        primary_oracle_bundle: OracleBundle<B>,
        aux_oracle_bundles_input: Vec<(String, OracleBundle<B>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let primary_log_size = primary_oracle_bundle.log_size();
        let mut row_aux: Vec<(String, OracleBundle<B>)> = Vec::new();
        let mut side_aux: Vec<(String, OracleBundle<B>)> = Vec::new();
        for (sid, aux) in aux_oracle_bundles_input {
            if aux.log_size() == primary_log_size {
                row_aux.push((sid, aux));
            } else {
                side_aux.push((sid, aux));
            }
        }
        Self::new_multi_split(primary_oracle_bundle, row_aux, side_aux, field_ref)
    }

    /// Constructs a multi-segment tracked column oracle with explicit
    /// row-vs-side classification. Preferred over [`Self::new_multi`].
    pub fn new_multi_split(
        primary_oracle_bundle: OracleBundle<B>,
        row_aux_input: Vec<(String, OracleBundle<B>)>,
        side_aux_input: Vec<(String, OracleBundle<B>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let mut aux_oracle_bundles: IndexMap<String, OracleBundle<B>> =
            IndexMap::with_capacity(row_aux_input.len() + side_aux_input.len());
        let mut side_aux_suffixes: IndexSet<String> =
            IndexSet::with_capacity(side_aux_input.len());
        for (sid, aux) in row_aux_input {
            assert!(
                !sid.is_empty(),
                "MultiSegment aux segment id must be non-empty (primary owns the empty id)"
            );
            assert!(
                !aux_oracle_bundles.contains_key(&sid),
                "duplicate aux segment id '{sid}' in MultiSegment column oracle"
            );
            aux_oracle_bundles.insert(sid, aux);
        }
        for (sid, aux) in side_aux_input {
            assert!(
                !sid.is_empty(),
                "MultiSegment aux segment id must be non-empty (primary owns the empty id)"
            );
            assert!(
                !aux_oracle_bundles.contains_key(&sid),
                "duplicate aux segment id '{sid}' in MultiSegment column oracle"
            );
            aux_oracle_bundles.insert(sid.clone(), aux);
            side_aux_suffixes.insert(sid);
        }
        Self::MultiSegment {
            primary_oracle_bundle,
            aux_oracle_bundles,
            side_aux_suffixes,
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

    /// Returns the log size of the tracked oracle. All row-domain
    /// segments in a multi-segment oracle share the same log size by
    /// construction.
    pub fn log_size(&self) -> usize {
        match self {
            Self::SingleSegment { oracle_bundle, .. } => oracle_bundle.log_size(),
            Self::MultiSegment {
                primary_oracle_bundle,
                ..
            } => primary_oracle_bundle.log_size(),
        }
    }

    /// Returns the primary data oracle.
    pub fn data_tracked_oracle(&self) -> TrackedOracle<B> {
        match self {
            Self::SingleSegment { oracle_bundle, .. } => oracle_bundle.data.clone(),
            Self::MultiSegment {
                primary_oracle_bundle,
                ..
            } => primary_oracle_bundle.data.clone(),
        }
    }

    /// Returns the primary segment's activator oracle.
    pub fn activator_tracked_oracle(&self) -> Option<TrackedOracle<B>> {
        match self {
            Self::SingleSegment { oracle_bundle, .. } => oracle_bundle.activator.clone(),
            Self::MultiSegment {
                primary_oracle_bundle,
                ..
            } => primary_oracle_bundle.activator.clone(),
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
            Self::MultiSegment {
                aux_oracle_bundles, ..
            } => 1 + aux_oracle_bundles.len(),
        }
    }

    /// Iterate `(id, data, activator)` over ROW-domain segments only:
    /// primary yields `id = None`, row-aux yields `id = Some(sid)`.
    /// Side-domain aux excluded via the explicit `side_aux_suffixes`
    /// marker (see the enum docstring for context).
    pub fn segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (Option<&str>, &TrackedOracle<B>, Option<&TrackedOracle<B>>)> + '_>
    {
        match self {
            Self::SingleSegment { oracle_bundle, .. } => Box::new(std::iter::once((
                None,
                &oracle_bundle.data,
                oracle_bundle.activator.as_ref(),
            ))),
            Self::MultiSegment {
                primary_oracle_bundle,
                aux_oracle_bundles,
                side_aux_suffixes,
                ..
            } => {
                let primary = std::iter::once((
                    None,
                    &primary_oracle_bundle.data,
                    primary_oracle_bundle.activator.as_ref(),
                ));
                let aux = aux_oracle_bundles
                    .iter()
                    .filter(move |(sid, _)| !side_aux_suffixes.contains(sid.as_str()))
                    .map(|(sid, aux)| (Some(sid.as_str()), &aux.data, aux.activator.as_ref()));
                Box::new(primary.chain(aux))
            }
        }
    }

    /// Look up ANY aux segment (row-domain or side-domain) by id.
    /// Returns `None` if the id is not registered (including for
    /// `SingleSegment` oracles).
    pub fn aux_segment(&self, aux_id: &str) -> Option<&OracleBundle<B>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                aux_oracle_bundles, ..
            } => aux_oracle_bundles.get(aux_id),
        }
    }

    /// Look up a side-domain segment specifically (returns `None` if the
    /// id resolves to a row-domain aux).
    pub fn side_segment(&self, side_id: &str) -> Option<&OracleBundle<B>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                aux_oracle_bundles,
                side_aux_suffixes,
                ..
            } => {
                if side_aux_suffixes.contains(side_id) {
                    aux_oracle_bundles.get(side_id)
                } else {
                    None
                }
            }
        }
    }

    /// Iterate `(suffix, aux)` over every side-domain segment in this
    /// column oracle, in insertion order. Empty for `SingleSegment`.
    pub fn side_segments_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (&str, &OracleBundle<B>)> + '_> {
        match self {
            Self::SingleSegment { .. } => Box::new(std::iter::empty()),
            Self::MultiSegment {
                aux_oracle_bundles,
                side_aux_suffixes,
                ..
            } => Box::new(
                aux_oracle_bundles
                    .iter()
                    .filter(move |(sid, _)| side_aux_suffixes.contains(sid.as_str()))
                    .map(|(sid, aux)| (sid.as_str(), aux)),
            ),
        }
    }

    /// Returns the verifier tracker.
    pub fn tracker_ref(&self) -> ArgVerifier<B> {
        let oracle = match self {
            Self::SingleSegment { oracle_bundle, .. } => &oracle_bundle.data,
            Self::MultiSegment {
                primary_oracle_bundle,
                ..
            } => &primary_oracle_bundle.data,
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
