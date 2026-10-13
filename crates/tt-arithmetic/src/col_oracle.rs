use ark_piop::SnarkBackend;
use ark_piop::verifier::{ArgVerifier, structs::oracle::TrackedOracle};
use datafusion::arrow::datatypes::FieldRef;
use derivative::Derivative;
use indexmap::{IndexMap, IndexSet};

/// Verifier-side mirror of [`crate::col::PolyBundle`].
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
/// Verifier-side mirror of [`crate::col::TrackedCol`], with the same
/// explicit row/side split.
pub enum TrackedColOracle<B: SnarkBackend> {
    SingleSegment {
        oracle_bundle: OracleBundle<B>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        primary_oracle_bundle: OracleBundle<B>,
        /// Row-domain and side-domain auxiliary segments, keyed by suffix.
        aux_oracle_bundles: IndexMap<String, OracleBundle<B>>,
        /// The keys of `aux_oracle_bundles` that are side-domain.
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
    /// A single-segment column oracle.
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

    /// [`Self::new_multi_split`] for a merged aux list, classifying each aux
    /// by `log_size` against the primary. Unreliable when a side domain is
    /// padded to the row size (see [`crate::col::TrackedCol::new_multi`]).
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

    /// A multi-segment column oracle from its primary bundle and its
    /// row-domain and side-domain aux bundles.
    pub fn new_multi_split(
        primary_oracle_bundle: OracleBundle<B>,
        row_aux_input: Vec<(String, OracleBundle<B>)>,
        side_aux_input: Vec<(String, OracleBundle<B>)>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        let mut aux_oracle_bundles: IndexMap<String, OracleBundle<B>> =
            IndexMap::with_capacity(row_aux_input.len() + side_aux_input.len());
        let mut side_aux_suffixes: IndexSet<String> = IndexSet::with_capacity(side_aux_input.len());
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
            // so its stored log_size is unconstrained: the sizes must match
            // only when both sides are non-constant.
            if !data_tracked_oracle.is_constant() && !activator.is_constant() {
                debug_assert_eq!(data_tracked_oracle.log_size(), activator.log_size());
            }
            debug_assert!(data_tracked_oracle.same_tracker(activator));
        }
    }

    /// The log size of the row domain, which all row-domain segments share.
    pub fn log_size(&self) -> usize {
        match self {
            Self::SingleSegment { oracle_bundle, .. } => oracle_bundle.log_size(),
            Self::MultiSegment {
                primary_oracle_bundle,
                ..
            } => primary_oracle_bundle.log_size(),
        }
    }

    /// The primary data oracle.
    pub fn data_tracked_oracle(&self) -> TrackedOracle<B> {
        match self {
            Self::SingleSegment { oracle_bundle, .. } => oracle_bundle.data.clone(),
            Self::MultiSegment {
                primary_oracle_bundle,
                ..
            } => primary_oracle_bundle.data.clone(),
        }
    }

    /// The activator of the primary data oracle.
    pub fn activator_tracked_oracle(&self) -> Option<TrackedOracle<B>> {
        match self {
            Self::SingleSegment { oracle_bundle, .. } => oracle_bundle.activator.clone(),
            Self::MultiSegment {
                primary_oracle_bundle,
                ..
            } => primary_oracle_bundle.activator.clone(),
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
                aux_oracle_bundles, ..
            } => 1 + aux_oracle_bundles.len(),
        }
    }

    /// `(id, data, activator)` of the row-domain segments only: the primary
    /// with `id = None`, then each row-domain aux with `id = Some(suffix)`.
    #[allow(clippy::type_complexity)]
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

    /// The aux segment `aux_id`, row-domain or side-domain.
    pub fn aux_segment(&self, aux_id: &str) -> Option<&OracleBundle<B>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment {
                aux_oracle_bundles, ..
            } => aux_oracle_bundles.get(aux_id),
        }
    }

    /// The side-domain segment `side_id`; `None` for a row-domain aux.
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

    /// `(suffix, aux)` of every side-domain segment, in insertion order.
    pub fn side_segments_iter(&self) -> Box<dyn Iterator<Item = (&str, &OracleBundle<B>)> + '_> {
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

    /// The primary data oracle times its activator, when it has one.
    pub fn activated_data_tracked_oracle(&self) -> TrackedOracle<B> {
        match self.activator_tracked_oracle() {
            Some(activator) => &self.data_tracked_oracle() * &activator,
            None => self.data_tracked_oracle(),
        }
    }

    /// A text table with the headers of the primary segment.
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
