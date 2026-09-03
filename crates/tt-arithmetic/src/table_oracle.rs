use crate::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD,
    col_oracle::{OracleBundle, TrackedColOracle},
    table::TrackedTable,
};
use ark_piop::SnarkBackend;
use ark_piop::{
    errors::SnarkResult,
    pcs::PCS,
    verifier::{ArgVerifier, errors::VerifierError, structs::oracle::TrackedOracle},
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use derivative::Derivative;
use indexmap::IndexMap;
use serde_json::{Value, from_slice as schema_from_slice, to_vec as schema_to_vec};
use std::fmt::Display;
use std::{convert::TryFrom, sync::Arc};

pub const CONSTRAINTS_SUMMARY_METADATA_KEY: &str = "tt.constraints.summary";
pub const EXTERNAL_COMMITMENT_SOURCE_METADATA_KEY: &str = "tt.external_commitment_source";
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// An abstraction of a tracked oracle to an arithmetized table in dbSNARK
/// A tracked oracle to an arithmetized table is represented by a set of tracked
/// oracles representing the columns
pub struct TrackedTableOracle<B: SnarkBackend> {
    /// The schema of the table, if any. Lists the flat Arrow fields
    /// (primary + all expanded segments) so downstream that reads the
    /// schema still sees the pre-expanded shape it expects.
    schema: Option<Schema>,
    /// The tracked column oracles of the table, keyed by SOURCE column
    /// name (not per-segment). Each `TrackedColOracle` owns its primary
    /// row-domain oracle, its auxiliary row-domain oracles (e.g.
    /// `__length`), and its side-domain oracles (e.g. `__chars`,
    /// `__orig_ind`, `__int_ind`, `__bnd`).
    tracked_col_oracles: IndexMap<FieldRef, TrackedColOracle<B>>,
    /// The log size of the table
    log_size: usize,
}

impl<B: SnarkBackend> Default for TrackedTableOracle<B> {
    fn default() -> Self {
        Self {
            schema: None,
            tracked_col_oracles: IndexMap::new(),
            log_size: 0,
        }
    }
}

impl<B: SnarkBackend> Display for TrackedTableOracle<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrackedTableOracle")
            .field(
                "num_total_tracked_col_oracles",
                &self.num_total_tracked_col_oracles(),
            )
            .field(
                "num_data_tracked_col_oracles",
                &self.num_data_tracked_col_oracles(),
            )
            .field("log_size", &self.log_size())
            .field("constraints", &constraints_summary_label(self.schema_ref()))
            .finish()
    }
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedTableOracle<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedTableOracle")
            .field(
                "num_total_tracked_col_oracles",
                &self.num_total_tracked_col_oracles(),
            )
            .field(
                "num_data_tracked_col_oracles",
                &self.num_data_tracked_col_oracles(),
            )
            .field("log_size", &self.log_size())
            .finish()
    }
}

impl<B: SnarkBackend> TrackedTableOracle<B> {
    /// Constructs a single-column oracle table and optionally appends an activator column.
    pub fn single_column_with_activator(
        field: FieldRef,
        data_oracle: TrackedOracle<B>,
        activator: Option<TrackedOracle<B>>,
    ) -> Self {
        let log_size = data_oracle.log_size();
        let mut oracles = IndexMap::new();
        oracles.insert(field, data_oracle);
        if let Some(activator_oracle) = activator {
            oracles.insert(ACTIVATOR_FIELD.clone(), activator_oracle);
        }
        TrackedTableOracle::new(None, oracles, log_size)
    }

    /// Constructs a new `TrackedTableOracle` from the flat schema-order
    /// oracles map. The flat input is regrouped internally into
    /// source-column-keyed `tracked_col_oracles`.
    pub fn new(
        schema: Option<Schema>,
        tracked_oracles: IndexMap<FieldRef, TrackedOracle<B>>,
        log_size: usize,
    ) -> Self {
        Self::new_with_side_cols(schema, tracked_oracles, log_size, IndexMap::new())
    }

    /// Constructs a new `TrackedTableOracle` from flat row-domain oracles
    /// + side oracles. Same regrouping logic as `new`.
    pub fn new_with_side_cols(
        schema: Option<Schema>,
        tracked_oracles: IndexMap<FieldRef, TrackedOracle<B>>,
        log_size: usize,
        side_cols: IndexMap<FieldRef, OracleBundle<B>>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&schema, &tracked_oracles, log_size).unwrap();
        }
        let tracked_col_oracles =
            regroup_flat_into_tracked_col_oracles(&tracked_oracles, &side_cols);
        Self {
            schema,
            tracked_col_oracles,
            log_size,
        }
    }

    /// Constructs a `TrackedTableOracle` directly from a
    /// source-column-keyed map (no regrouping).
    pub fn new_from_col_oracles(
        schema: Option<Schema>,
        tracked_col_oracles: IndexMap<FieldRef, TrackedColOracle<B>>,
        log_size: usize,
    ) -> Self {
        Self {
            schema,
            tracked_col_oracles,
            log_size,
        }
    }

    /// Read-only access to side-domain oracles, derived from source-column
    /// storage on demand. Synthesized side FieldRefs inherit the source
    /// column's metadata.
    pub fn side_cols(&self) -> IndexMap<FieldRef, OracleBundle<B>> {
        let mut out: IndexMap<FieldRef, OracleBundle<B>> = IndexMap::new();
        for (field, col) in self.tracked_col_oracles.iter() {
            for (suffix, side) in col.side_segments_iter() {
                let side_field = Arc::new(
                    Field::new(
                        format!("{}{}", field.name(), suffix),
                        field.data_type().clone(),
                        field.is_nullable(),
                    )
                    .with_metadata(field.metadata().clone()),
                );
                out.insert(side_field, side.clone());
            }
        }
        out
    }

    /// Insert (or attach) a side-domain oracle to the source column that
    /// owns it. If the target col is `SingleSegment`, it is promoted to
    /// `MultiSegment`.
    pub fn insert_side_col(&mut self, field: FieldRef, side: OracleBundle<B>) {
        let base_name = crate::encoding::segment_base_name(field.name())
            .expect("insert_side_col: field name must carry a known segment suffix")
            .to_string();
        let suffix = field.name()[base_name.len()..].to_string();
        let target_field = self
            .tracked_col_oracles
            .keys()
            .find(|f| f.name() == base_name.as_str())
            .cloned()
            .expect("insert_side_col: no source column found for side segment");
        let existing = self
            .tracked_col_oracles
            .swap_remove(&target_field)
            .expect("insert_side_col: source column disappeared");
        let promoted = match existing {
            TrackedColOracle::SingleSegment {
                oracle_bundle,
                field_ref,
            } => TrackedColOracle::new_multi_split(
                oracle_bundle,
                Vec::new(),
                vec![(suffix, side)],
                field_ref,
            ),
            TrackedColOracle::MultiSegment {
                primary_oracle_bundle,
                mut aux_oracle_bundles,
                mut side_aux_suffixes,
                field_ref,
            } => {
                aux_oracle_bundles.insert(suffix.clone(), side);
                side_aux_suffixes.insert(suffix);
                TrackedColOracle::MultiSegment {
                    primary_oracle_bundle,
                    aux_oracle_bundles,
                    side_aux_suffixes,
                    field_ref,
                }
            }
        };
        self.tracked_col_oracles.insert(target_field, promoted);
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        schema: &Option<Schema>,
        tracked_oracles: &IndexMap<FieldRef, TrackedOracle<B>>,
        log_size: usize,
    ) -> SnarkResult<()> {
        // All column oracles have the same tracker
        let first_oracle = tracked_oracles
            .values()
            .next()
            .expect("table should have columns");
        tracked_oracles.values().for_each(|oracle| {
            assert!(
                first_oracle.same_tracker(oracle),
                "All columns must share the same tracker"
            );
        });

        // Folded-constant oracles evaluate identically on any hypercube,
        // so their stored log_size is not required to match — mirrors the
        // relaxation in `TrackedColOracle::check_new_args`.
        tracked_oracles.values().for_each(|oracle| {
            if !oracle.is_constant() {
                assert_eq!(
                    oracle.log_size(),
                    log_size,
                    "All columns must have the same log size as the table"
                );
            }
        });

        if let Some(schema) = &schema {
            schema
                .fields()
                .iter()
                .zip(tracked_oracles.keys())
                .for_each(|(f1, f2)| {
                    assert_eq!(f1, f2, "Schema fields must match the tracked oracle fields");
                });
        }
        Ok(())
    }

    /// Returns the flat schema-order tracked oracles map, derived on
    /// demand from the source-column-keyed storage.
    pub fn tracked_oracles(&self) -> IndexMap<FieldRef, TrackedOracle<B>> {
        let mut out: IndexMap<FieldRef, TrackedOracle<B>> = IndexMap::new();
        for (field, col) in self.tracked_col_oracles.iter() {
            for (suffix, oracle, _act) in col.segments_iter() {
                let seg_field = match suffix {
                    None => field.clone(),
                    Some(sid) => Arc::new(
                        Field::new(
                            format!("{}{}", field.name(), sid),
                            field.data_type().clone(),
                            field.is_nullable(),
                        )
                        .with_metadata(field.metadata().clone()),
                    ),
                };
                out.insert(seg_field, oracle.clone());
            }
        }
        out
    }

    /// Iterator over the flat schema-order tracked oracles. Yields owned
    /// tuples (materialized on demand).
    pub fn tracked_oracles_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (FieldRef, TrackedOracle<B>)> + '_> {
        Box::new(self.tracked_col_oracles.iter().flat_map(|(field, col)| {
            col.segments_iter()
                .map(move |(suffix, oracle, _act)| {
                    let seg_field = match suffix {
                        None => field.clone(),
                        Some(sid) => Arc::new(
                            Field::new(
                                format!("{}{}", field.name(), sid),
                                field.data_type().clone(),
                                field.is_nullable(),
                            )
                            .with_metadata(field.metadata().clone()),
                        ),
                    };
                    (seg_field, oracle.clone())
                })
                .collect::<Vec<_>>()
                .into_iter()
        }))
    }

    /// Direct accessor for the source-column-keyed storage.
    pub fn tracked_col_oracles(&self) -> IndexMap<FieldRef, TrackedColOracle<B>> {
        self.tracked_col_oracles.clone()
    }

    /// Iterator over source-column-keyed entries (borrowed refs).
    pub fn tracked_col_oracles_iter(
        &self,
    ) -> impl Iterator<Item = (&FieldRef, &TrackedColOracle<B>)> {
        self.tracked_col_oracles.iter()
    }

    /// Look up a specific side-domain oracle by source column name and
    /// suffix.
    pub fn side_segment(
        &self,
        col_name: &str,
        suffix: &str,
    ) -> Option<&OracleBundle<B>> {
        self.tracked_col_oracles
            .iter()
            .find(|(f, _)| f.name() == col_name)
            .and_then(|(_, col)| col.side_segment(suffix))
    }

    /// Indices into the flat schema-order view of all non-system columns.
    pub fn data_tracked_oracles_indices(&self) -> Vec<usize> {
        self.tracked_oracles()
            .keys()
            .enumerate()
            .filter_map(|(idx, field)| (!crate::is_system_column(field.name())).then_some(idx))
            .collect()
    }

    /// Returns the optional schema of the table
    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    pub fn schema_ref(&self) -> Option<&Schema> {
        self.schema.as_ref()
    }

    /// Returns the log size of the table
    pub fn log_size(&self) -> usize {
        self.log_size
    }

    /// Returns the size of the table
    pub fn size(&self) -> usize {
        1 << self.log_size()
    }

    /// Pretty-print the tracked table oracle by showing only the column names.
    pub fn pretty_string(&self) -> String {
        let flat = self.tracked_oracles();
        if flat.is_empty() {
            return "TrackedTableOracle<empty>".to_string();
        }

        let headers: Vec<String> = flat
            .keys()
            .map(|field| {
                let name = field.name();
                if name.is_empty() {
                    "-".to_string()
                } else {
                    name.to_string()
                }
            })
            .collect();

        let widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();

        let mut out = String::new();
        out.push_str(&border_line(&widths));
        out.push_str(&row_line(&headers, &widths));
        out.push_str(&border_line(&widths));
        out
    }

    /// Folds the specified column oracles by flat schema-order indices.
    pub fn fold(&self, col_inds: &[usize], challs: &[B::F]) -> TrackedColOracle<B> {
        let flat = self.tracked_oracles();
        let first_idx = *col_inds
            .first()
            .expect("fold requires at least one column index");
        let (_, first_oracle) = flat
            .get_index(first_idx)
            .expect("column oracle index out of bounds");
        if col_inds.len() == 1 {
            return TrackedColOracle::new(
                first_oracle.clone(),
                self.activator_tracked_poly(),
                None,
            );
        }

        debug_assert_eq!(col_inds.len(), challs.len());
        let first_chall = challs
            .first()
            .copied()
            .expect("fold requires at least one challenge");
        let mut folded: TrackedOracle<B> = first_oracle.mul_scalar_oracle(first_chall);
        for (&col_idx, &chall) in col_inds.iter().zip(challs).skip(1) {
            let (_, col_oracle) = flat
                .get_index(col_idx)
                .expect("column oracle index out of bounds");
            folded += &col_oracle.mul_scalar_oracle(chall);
        }
        TrackedColOracle::new(folded, self.activator_tracked_poly(), None)
    }

    /// Folds all the data (i.e. excluding the activator column) tracked column
    /// oracles
    pub fn fold_all_data_oracles(&self, challs: &[B::F]) -> TrackedColOracle<B> {
        let data_col_indices = self.data_tracked_oracles_indices();
        self.fold(&data_col_indices, challs)
    }

    /// Returns the tracked column oracle at the specified flat schema-order
    /// index, wrapped as SingleSegment.
    pub fn tracked_col_oracle_by_ind(&self, col_ind: usize) -> TrackedColOracle<B> {
        let flat = self.tracked_oracles();
        let (field_ref, data_tracked_oracle) = flat
            .get_index(col_ind)
            .expect("column oracle not found");
        TrackedColOracle::new(
            data_tracked_oracle.clone(),
            self.activator_tracked_poly(),
            Some(field_ref.clone()),
        )
    }

    /// Returns the tracked column oracle with the specified source column
    /// name, fully grouped. Returns `None` if `name` is not a source
    /// column here.
    pub fn tracked_col_oracle_by_name(&self, name: &str) -> Option<TrackedColOracle<B>> {
        self.tracked_col_oracles
            .iter()
            .find_map(|(f, c)| (f.name() == name).then(|| c.clone()))
    }

    /// Returns the tracked column oracles at the specified flat schema-order
    /// indices.
    pub fn tracked_col_oracles_by_indices(&self, indices: &[usize]) -> Vec<TrackedColOracle<B>> {
        indices
            .iter()
            .map(|&i| self.tracked_col_oracle_by_ind(i))
            .collect()
    }

    /// Returns a subtable oracle containing the tracked columns at the
    /// specified flat schema-order indices, plus the activator (if any).
    /// Aux/side segments of retained source columns are carried over
    /// intact.
    pub fn tracked_subtable_by_indices(&self, indices: &[usize]) -> TrackedTableOracle<B> {
        let flat = self.tracked_oracles();
        // Verifier mirror of `TrackedTable::tracked_subtable_by_indices` —
        // retain by source-column identity, not by name, so a self-join's two
        // same-named columns stay distinguishable.
        let owners: Vec<FieldRef> = self
            .tracked_col_oracles
            .iter()
            .flat_map(|(field, col)| col.segments_iter().map(move |_| field.clone()))
            .collect();
        let mut retained: indexmap::IndexSet<FieldRef> = indexmap::IndexSet::new();
        if owners.len() == flat.len() {
            for &idx in indices {
                retained.insert(
                    owners
                        .get(idx)
                        .expect("column oracle index out of bounds")
                        .clone(),
                );
            }
        } else {
            for &idx in indices {
                let (field, _) = flat.get_index(idx).expect("column oracle index out of bounds");
                let base = crate::encoding::segment_base_name(field.name())
                    .unwrap_or_else(|| field.name());
                for (f, _) in self.tracked_col_oracles.iter() {
                    if f.name() == base {
                        retained.insert(f.clone());
                    }
                }
            }
        }
        for (field, _) in self.tracked_col_oracles.iter() {
            if crate::is_system_column(field.name()) {
                retained.insert(field.clone());
            }
        }

        let mut sub_cols: IndexMap<FieldRef, TrackedColOracle<B>> = IndexMap::new();
        for (field, col) in self.tracked_col_oracles.iter() {
            if retained.contains(field) {
                sub_cols.insert(field.clone(), col.clone());
            }
        }

        let sub_schema = self.schema.as_ref().map(|schema| {
            let sub_flat_names: std::collections::HashSet<String> = sub_cols
                .iter()
                .flat_map(|(f, c)| {
                    c.segments_iter().map(move |(suffix, _, _)| match suffix {
                        None => f.name().to_string(),
                        Some(sid) => format!("{}{}", f.name(), sid),
                    })
                })
                .collect();
            let name_is_unique =
                |n: &str| schema.fields().iter().filter(|g| g.name() == n).count() == 1;
            let sub_flat_fields: Vec<Field> = sub_cols
                .iter()
                .flat_map(|(f, c)| {
                    c.segments_iter().map(move |(suffix, _, _)| match suffix {
                        None => f.as_ref().clone(),
                        Some(sid) => Field::new(
                            format!("{}{}", f.name(), sid),
                            f.data_type().clone(),
                            f.is_nullable(),
                        )
                        .with_metadata(f.metadata().clone()),
                    })
                })
                .collect();
            let fields = schema
                .fields()
                .iter()
                .filter(|f| {
                    sub_flat_fields.iter().any(|sf| sf == f.as_ref())
                        || (sub_flat_names.contains(f.name()) && name_is_unique(f.name()))
                })
                .map(|f| f.as_ref().clone())
                .collect::<Vec<Field>>();
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });

        TrackedTableOracle::new_from_col_oracles(sub_schema, sub_cols, self.log_size)
    }

    /// Returns all the tracked column oracles (flat schema-order, each
    /// wrapped as SingleSegment).
    pub fn all_tracked_col_oracles(&self) -> Vec<TrackedColOracle<B>> {
        self.tracked_col_oracles_by_indices(
            &(0..self.num_total_tracked_col_oracles()).collect::<Vec<usize>>(),
        )
    }

    /// Number of flat schema-order ROW-DOMAIN columns including
    /// activator. Matches the length of `tracked_oracles()` (side
    /// segments live in `side_cols()` and are counted separately).
    pub fn num_total_tracked_col_oracles(&self) -> usize {
        self.tracked_col_oracles
            .values()
            .map(|c| c.segments_iter().count())
            .sum()
    }

    /// Number of flat schema-order data columns (excluding system).
    pub fn num_data_tracked_col_oracles(&self) -> usize {
        self.tracked_oracles()
            .keys()
            .filter(|field| !crate::is_system_column(field.name()))
            .count()
    }

    /// Returns the tracked oracle of the activator column, if any.
    pub fn activator_tracked_poly(&self) -> Option<TrackedOracle<B>> {
        self.tracked_col_oracles.iter().find_map(|(field, col)| {
            (field.name() == ACTIVATOR_COL_NAME).then(|| col.data_tracked_oracle())
        })
    }

    /// Constructs an `TrackedTableOracle` from an `TrackedTable` by tracking
    /// the column and activator polynomials using the provided verifier
    /// It's assumed that the verifier already has the commitments of the
    /// polynomials being tracked
    pub fn from_tracked_table(
        table: TrackedTable<B>,
        verifier: &mut ArgVerifier<B>,
    ) -> SnarkResult<Self> {
        let schema = table.schema().clone();
        let log_size = table.log_size();

        let mut data_map = IndexMap::with_capacity(table.num_total_tracked_cols());
        for col in table.all_tracked_cols() {
            let poly = col.data_tracked_poly();
            let field_ref = col.field_ref().clone().unwrap_or_else(|| {
                panic!("All columns in a tracked table must have a field reference")
            });
            if poly.is_constant() {
                return Err(VerifierError::VerifierCheckFailed(
                    "Table column polynomial is constant; expected commitment id".into(),
                )
                .into());
            }
            let oracle = verifier.track_mv_com_by_id(poly.id())?;
            data_map.insert(field_ref.clone(), oracle);
        }

        Ok(Self::new(schema, data_map, log_size))
    }
}

/// Regroup a flat `IndexMap<FieldRef, TrackedOracle<B>>` + a flat
/// `IndexMap<FieldRef, OracleBundle<B>>` into the source-column-keyed
/// shape stored by `TrackedTableOracle`. Verifier-side mirror of
/// `regroup_flat_into_tracked_cols` in `table.rs`. Orphan aux fields
/// (aux whose primary is absent from the flat input) become their own
/// SingleSegment entries — preserves scratch-table semantics.
fn regroup_flat_into_tracked_col_oracles<B: SnarkBackend>(
    tracked_oracles: &IndexMap<FieldRef, TrackedOracle<B>>,
    side_cols: &IndexMap<FieldRef, OracleBundle<B>>,
) -> IndexMap<FieldRef, TrackedColOracle<B>> {
    let shared_activator = tracked_oracles.iter().find_map(|(field, oracle)| {
        (field.name() == ACTIVATOR_COL_NAME).then(|| oracle.clone())
    });
    let primary_present: std::collections::HashSet<String> = tracked_oracles
        .keys()
        .filter(|f| crate::encoding::segment_base_name(f.name()).is_none())
        .map(|f| f.name().to_string())
        .collect();
    // Mirror of the prover-side `ambiguous_primaries`; see
    // `crate::table::regroup_flat_into_tracked_cols`.
    let ambiguous_primaries: std::collections::HashSet<String> = {
        let mut seen = std::collections::HashSet::new();
        tracked_oracles
            .keys()
            .filter(|f| crate::encoding::segment_base_name(f.name()).is_none())
            .filter(|f| !seen.insert(f.name().to_string()))
            .map(|f| f.name().to_string())
            .collect()
    };
    let mut out = IndexMap::with_capacity(tracked_oracles.len());
    for (field, oracle) in tracked_oracles.iter() {
        if let Some(base) = crate::encoding::segment_base_name(field.name()) {
            if primary_present.contains(base) {
                continue;
            }
            out.insert(
                field.clone(),
                TrackedColOracle::new(
                    oracle.clone(),
                    shared_activator.clone(),
                    Some(field.clone()),
                ),
            );
            continue;
        }
        let primary_name = field.name();
        let mut row_aux_bundles: Vec<(String, OracleBundle<B>)> = Vec::new();
        let mut side_aux_bundles: Vec<(String, OracleBundle<B>)> = Vec::new();
        for (aux_field, aux_oracle) in tracked_oracles.iter() {
            if aux_field.name() == primary_name {
                continue;
            }
            if crate::table::aux_belongs_to(aux_field, field, &ambiguous_primaries) {
                let suffix = &aux_field.name()[primary_name.len()..];
                row_aux_bundles.push((
                    suffix.to_string(),
                    OracleBundle::new(aux_oracle.clone(), shared_activator.clone()),
                ));
            }
        }
        for (side_field, side) in side_cols.iter() {
            if crate::table::aux_belongs_to(side_field, field, &ambiguous_primaries) {
                let suffix = &side_field.name()[primary_name.len()..];
                side_aux_bundles.push((suffix.to_string(), side.clone()));
            }
        }
        let col = if row_aux_bundles.is_empty() && side_aux_bundles.is_empty() {
            TrackedColOracle::new(
                oracle.clone(),
                shared_activator.clone(),
                Some(field.clone()),
            )
        } else {
            // Preserve the row-vs-side split the caller already knows
            // (tracked_oracles → row, side_cols → side). See prover-side
            // regroup_flat_into_tracked_cols for the equivalent rationale.
            TrackedColOracle::new_multi_split(
                OracleBundle::new(oracle.clone(), shared_activator.clone()),
                row_aux_bundles,
                side_aux_bundles,
                Some(field.clone()),
            )
        };
        out.insert(field.clone(), col);
    }
    out
}

/// Per-side-segment commitment pair (data + activator) plus sizing metadata.
/// Mirrors `ArithSideCol` at the commitment layer.
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""), Debug(bound = ""))]
pub struct ArithSideColOracle<B: SnarkBackend> {
    pub data: <B::MvPCS as PCS<B::F>>::Commitment,
    pub activator: <B::MvPCS as PCS<B::F>>::Commitment,
    pub log_size: usize,
    pub active_len: usize,
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""), Debug(bound = ""))]
/// An abstraction of an oracle to an arithmetized table in dbSNARK
/// An arithmetic table might not be tracked and can be serialized and
/// deserialized
pub struct ArithTableOracle<B: SnarkBackend> {
    _phantom: std::marker::PhantomData<B>,
    schema: Option<Schema>,
    commitments: IndexMap<FieldRef, <B::MvPCS as PCS<B::F>>::Commitment>,
    log_size: usize,
    /// Side-domain commitments (data + activator pairs) keyed by side
    /// segment field reference (e.g. `<col>__chars`).
    side_commitments: IndexMap<FieldRef, ArithSideColOracle<B>>,
}

impl<B: SnarkBackend> Display for ArithTableOracle<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArithTableOracle")
            .field("num_total_cols", &self.num_total_cols())
            .field("log_size", &self.log_size())
            .field("constraints", &constraints_summary_label(self.schema_ref()))
            .finish()
    }
}

fn constraints_summary_label(schema: Option<&Schema>) -> Option<String> {
    let raw = schema?
        .metadata()
        .get(CONSTRAINTS_SUMMARY_METADATA_KEY)?
        .as_str();
    let parsed = serde_json::from_str::<Value>(raw).ok()?;

    let pk_cols = parsed
        .get("primary_key_columns")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let fk_cols = parsed
        .get("foreign_keys")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|fk| {
                    let col = fk.get("column")?.as_str()?;
                    let table = fk.get("ref_table")?.as_str()?;
                    Some(format!("{col}->{table}"))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let pk = if pk_cols.is_empty() {
        "none".to_string()
    } else {
        pk_cols.join("|")
    };
    let fk = if fk_cols.is_empty() {
        "none".to_string()
    } else {
        fk_cols.join("|")
    };
    Some(format!("pk:{pk}; fk:{fk}"))
}

impl<B: SnarkBackend> ArithTableOracle<B> {
    /// Constructs a new `ArithTableOracle` with no side commitments.
    pub fn new(
        schema: Option<Schema>,
        commitments: IndexMap<FieldRef, <B::MvPCS as PCS<B::F>>::Commitment>,
        log_size: usize,
    ) -> Self {
        Self::new_with_side_commitments(schema, commitments, log_size, IndexMap::new())
    }

    /// Constructs a new `ArithTableOracle` with explicit side-domain
    /// commitments.
    pub fn new_with_side_commitments(
        schema: Option<Schema>,
        commitments: IndexMap<FieldRef, <B::MvPCS as PCS<B::F>>::Commitment>,
        log_size: usize,
        side_commitments: IndexMap<FieldRef, ArithSideColOracle<B>>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&schema, &commitments, log_size).unwrap();
        }
        Self {
            _phantom: std::marker::PhantomData,
            schema,
            commitments,
            log_size,
            side_commitments,
        }
    }

    /// Read-only access to side-domain commitment entries.
    pub fn side_commitments(&self) -> &IndexMap<FieldRef, ArithSideColOracle<B>> {
        &self.side_commitments
    }
    #[cfg(debug_assertions)]
    fn check_new_args(
        schema: &Option<Schema>,
        commitments: &IndexMap<FieldRef, <B::MvPCS as PCS<B::F>>::Commitment>,
        _log_size: usize,
    ) -> SnarkResult<()> {
        // If schema is provided, it must match the fields of the commitments
        if let Some(schema) = &schema {
            schema
                .fields()
                .iter()
                .zip(commitments.keys())
                .for_each(|(f1, f2)| {
                    assert_eq!(f1, f2, "Schema fields must match the comitment fields");
                });
        }
        Ok(())
    }

    /// Returns the map of column commitments in the table
    pub fn commitments(&self) -> &IndexMap<FieldRef, <B::MvPCS as PCS<B::F>>::Commitment> {
        &self.commitments
    }

    /// Returns the log size of the table
    pub fn log_size(&self) -> usize {
        self.log_size
    }

    /// Returns the size of the table
    pub fn size(&self) -> usize {
        1 << self.log_size()
    }

    /// Number of columns in the table including activator (if any)
    pub fn num_total_cols(&self) -> usize {
        self.commitments.len()
    }

    /// Returns the optional schema of the table
    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }
    pub fn schema_ref(&self) -> Option<&Schema> {
        self.schema.as_ref()
    }

    /// Returns the optional table-level constraint summary JSON generated during commitment.
    pub fn constraints_summary_json(&self) -> Option<&str> {
        self.schema
            .as_ref()
            .and_then(|schema| schema.metadata().get(CONSTRAINTS_SUMMARY_METADATA_KEY))
            .map(String::as_str)
    }

    pub fn is_external_commitment_source(&self) -> bool {
        self.schema
            .as_ref()
            .and_then(|schema| {
                schema
                    .metadata()
                    .get(EXTERNAL_COMMITMENT_SOURCE_METADATA_KEY)
            })
            .is_some_and(|value| value == "true")
    }

    pub fn with_external_commitment_source(mut self, is_external: bool) -> Self {
        if let Some(schema) = self.schema.take() {
            let mut metadata = schema.metadata().clone();
            metadata.insert(
                EXTERNAL_COMMITMENT_SOURCE_METADATA_KEY.to_string(),
                if is_external { "true" } else { "false" }.to_string(),
            );
            self.schema = Some(Schema::new_with_metadata(schema.fields().clone(), metadata));
        }
        self
    }
    /// Constructs an `ArithTableOracle` from a `TrackedTableOracle` by
    /// extracting
    pub fn from_tracked_table_oracle(table_oracle: &TrackedTableOracle<B>) -> Self
    where
        <B::MvPCS as PCS<B::F>>::Commitment: Clone,
    {
        let commitments = table_oracle
            .tracked_oracles()
            .iter()
            .map(|(field_ref, oracle)| (field_ref.clone(), oracle.commitment()))
            .collect();
        let side_commitments = table_oracle
            .side_cols()
            .iter()
            .map(|(field_ref, side)| {
                (
                    field_ref.clone(),
                    ArithSideColOracle {
                        data: side.data.commitment(),
                        activator: side
                            .activator
                            .as_ref()
                            .expect("side segment must carry a tracked activator")
                            .commitment(),
                        log_size: side.log_size(),
                        // `active_len` is not carried on the tracked
                        // layer; no downstream consumer reads this
                        // field on `ArithSideColOracle`. See
                        // verifier/passes/tracking.rs for the parallel
                        // placeholder used on the verifier side.
                        active_len: 0,
                    },
                )
            })
            .collect();
        Self {
            _phantom: std::marker::PhantomData,
            schema: table_oracle.schema(),
            commitments,
            log_size: table_oracle.log_size(),
            side_commitments,
        }
    }

    /// Returns the oracle of the activator column, if any
    pub fn activator_commitment(&self) -> Option<&<B::MvPCS as PCS<B::F>>::Commitment> {
        self.commitments
            .iter()
            .find_map(|(field, comm)| (field.name() == ACTIVATOR_COL_NAME).then_some(comm))
    }
}

impl<B: SnarkBackend> CanonicalSerialize for ArithTableOracle<B>
where
    <B::MvPCS as PCS<B::F>>::Commitment: CanonicalSerialize + Valid,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        let has_schema = self.schema.is_some();
        has_schema.serialize_with_mode(&mut writer, compress)?;

        if let Some(schema) = &self.schema {
            let schema_bytes =
                schema_to_vec(schema).map_err(|_| SerializationError::InvalidData)?;
            schema_bytes.serialize_with_mode(&mut writer, compress)?;
        }

        let ordered_fields: Vec<FieldRef> = if let Some(schema) = &self.schema {
            schema.fields().iter().cloned().collect()
        } else {
            let mut keys = self.commitments.keys().cloned().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.name().cmp(b.name()));
            keys
        };

        let count = ordered_fields.len() as u64;
        count.serialize_with_mode(&mut writer, compress)?;

        for field_ref in ordered_fields.iter() {
            let commitment = self
                .commitments
                .get(field_ref)
                .ok_or(SerializationError::InvalidData)?;
            commitment.serialize_with_mode(&mut writer, compress)?;
        }

        (self.log_size as u64).serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut size = self.schema.is_some().serialized_size(compress);

        if let Some(schema) = &self.schema {
            let schema_bytes = schema_to_vec(schema).expect("schema serialization should succeed");
            size += schema_bytes.serialized_size(compress);
        }

        let ordered_fields: Vec<FieldRef> = if let Some(schema) = &self.schema {
            schema.fields().iter().cloned().collect()
        } else {
            let mut keys = self.commitments.keys().cloned().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.name().cmp(b.name()));
            keys
        };

        size += (ordered_fields.len() as u64).serialized_size(compress);
        for field_ref in ordered_fields.iter() {
            let commitment = self
                .commitments
                .get(field_ref)
                .expect("commitment missing for field");
            size += commitment.serialized_size(compress);
        }

        size + (self.log_size as u64).serialized_size(compress)
    }
}

impl<B: SnarkBackend + Sync> CanonicalDeserialize for ArithTableOracle<B>
where
    <B::MvPCS as PCS<B::F>>::Commitment: CanonicalDeserialize + Valid,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let has_schema = bool::deserialize_with_mode(&mut reader, compress, validate)?;
        let schema = if has_schema {
            let schema_bytes = Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
            Some(
                schema_from_slice::<Schema>(&schema_bytes)
                    .map_err(|_| SerializationError::InvalidData)?,
            )
        } else {
            None
        };

        let count = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let count_usize = usize::try_from(count).map_err(|_| SerializationError::InvalidData)?;
        let mut commitments = IndexMap::with_capacity(count_usize);

        let ordered_fields: Vec<FieldRef> = if let Some(schema) = &schema {
            let fields = schema.fields().iter().cloned().collect::<Vec<_>>();
            if fields.len() != count_usize {
                return Err(SerializationError::InvalidData);
            }
            fields
        } else {
            (0..count)
                .map(|idx| {
                    let field_name = format!("__col_{idx}");
                    Arc::new(Field::new(&field_name, DataType::Null, true))
                })
                .collect()
        };

        for field_ref in ordered_fields {
            let commitment = <B::MvPCS as PCS<B::F>>::Commitment::deserialize_with_mode(
                &mut reader,
                compress,
                validate,
            )?;
            commitments.insert(field_ref, commitment);
        }

        let log_size_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let log_size =
            usize::try_from(log_size_raw).map_err(|_| SerializationError::InvalidData)?;

        Ok(Self {
            _phantom: std::marker::PhantomData,
            schema,
            commitments,
            log_size,
            side_commitments: IndexMap::new(),
        })
    }
}

impl<B: SnarkBackend + Sync> Valid for ArithTableOracle<B>
where
    <B::MvPCS as PCS<B::F>>::Commitment: Valid,
{
    fn check(&self) -> Result<(), SerializationError> {
        for commitment in self.commitments.values() {
            commitment.check()?;
        }
        Ok(())
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
