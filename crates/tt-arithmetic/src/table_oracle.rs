use crate::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, col_oracle::TrackedColOracle, table::TrackedTable,
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
/// Verifier-side mirror of `TrackedSideCol`. Carries a single side-domain
/// oracle pair (data, activator) with its own `log_size`.
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
pub struct TrackedSideColOracle<B: SnarkBackend> {
    pub data: TrackedOracle<B>,
    pub activator: TrackedOracle<B>,
    pub log_size: usize,
    pub active_len: usize,
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedSideColOracle<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedSideColOracle")
            .field("log_size", &self.log_size)
            .field("active_len", &self.active_len)
            .finish()
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// An abstraction of a tracked oracle to an arithmetized table in dbSNARK
/// A tracked oracle to an arithmetized table is represented by a set of tracked
/// oracles representing the columns
pub struct TrackedTableOracle<B: SnarkBackend> {
    /// The schema of the table, if any
    schema: Option<Schema>,
    /// The oracles representing the columns, stored in schema order
    tracked_oracles: IndexMap<FieldRef, TrackedOracle<B>>,
    /// The log size of the table
    log_size: usize,
    /// Side-domain tracked oracles (e.g. `__chars`) keyed by side field ref.
    side_cols: IndexMap<FieldRef, TrackedSideColOracle<B>>,
}

impl<B: SnarkBackend> Default for TrackedTableOracle<B> {
    fn default() -> Self {
        Self {
            schema: None,
            tracked_oracles: IndexMap::new(),
            log_size: 0,
            side_cols: IndexMap::new(),
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

    /// Constructs a new `TrackedTableOracle` from the provided schema (if any),
    /// tracked oracles, and log size of the table (no side columns).
    pub fn new(
        schema: Option<Schema>,
        tracked_oracles: IndexMap<FieldRef, TrackedOracle<B>>,
        log_size: usize,
    ) -> Self {
        Self::new_with_side_cols(schema, tracked_oracles, log_size, IndexMap::new())
    }

    /// Constructs a new `TrackedTableOracle` with explicit side-domain
    /// oracles.
    pub fn new_with_side_cols(
        schema: Option<Schema>,
        tracked_oracles: IndexMap<FieldRef, TrackedOracle<B>>,
        log_size: usize,
        side_cols: IndexMap<FieldRef, TrackedSideColOracle<B>>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&schema, &tracked_oracles, log_size).unwrap();
        }
        Self {
            schema,
            tracked_oracles,
            log_size,
            side_cols,
        }
    }

    /// Read-only access to side-domain oracles.
    pub fn side_cols(&self) -> &IndexMap<FieldRef, TrackedSideColOracle<B>> {
        &self.side_cols
    }

    /// Insert (or replace) a side-domain oracle on this table.
    pub fn insert_side_col(&mut self, field: FieldRef, side: TrackedSideColOracle<B>) {
        self.side_cols.insert(field, side);
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

    /// Returns the vector of raw column oracles in the table
    pub fn tracked_oracles(&self) -> IndexMap<FieldRef, TrackedOracle<B>> {
        self.tracked_oracles.clone()
    }

    pub fn tracked_oracles_iter(&self) -> impl Iterator<Item = (&FieldRef, &TrackedOracle<B>)> {
        self.tracked_oracles.iter()
    }

    /// Bridge accessor: reconstructs a source-column-keyed view of this
    /// table oracle by grouping the flat `tracked_oracles` + `side_cols`
    /// entries by source column name (via `segment_base_name` /
    /// `is_segment_of`). Mirrors `TrackedTable::tracked_cols`.
    pub fn tracked_col_oracles(&self) -> IndexMap<FieldRef, TrackedColOracle<B>> {
        let mut out = IndexMap::with_capacity(self.tracked_oracles.len());
        let shared_activator = self.activator_tracked_poly();
        for (field, oracle) in self.tracked_oracles.iter() {
            if crate::encoding::segment_base_name(field.name()).is_some() {
                continue;
            }
            let primary_name = field.name();
            let mut aux_segments: Vec<(String, TrackedOracle<B>, Option<TrackedOracle<B>>)> =
                Vec::new();
            for (aux_field, aux_oracle) in self.tracked_oracles.iter() {
                if aux_field.name() == primary_name {
                    continue;
                }
                if let Some(base) = crate::encoding::segment_base_name(aux_field.name())
                    && base == primary_name
                {
                    let suffix = &aux_field.name()[primary_name.len()..];
                    aux_segments.push((
                        suffix.to_string(),
                        aux_oracle.clone(),
                        shared_activator.clone(),
                    ));
                }
            }
            let mut side_segments: Vec<(String, TrackedSideColOracle<B>)> = Vec::new();
            for (side_field, side) in self.side_cols.iter() {
                if let Some(base) = crate::encoding::segment_base_name(side_field.name())
                    && base == primary_name
                {
                    let suffix = &side_field.name()[primary_name.len()..];
                    side_segments.push((suffix.to_string(), side.clone()));
                }
            }
            let col = if aux_segments.is_empty() && side_segments.is_empty() {
                TrackedColOracle::new(
                    oracle.clone(),
                    shared_activator.clone(),
                    Some(field.clone()),
                )
            } else {
                TrackedColOracle::new_multi(
                    oracle.clone(),
                    shared_activator.clone(),
                    aux_segments,
                    side_segments,
                    Some(field.clone()),
                )
            };
            out.insert(field.clone(), col);
        }
        out
    }

    /// Look up a specific side-domain oracle by source column name and
    /// suffix. Bridge accessor; reads directly from today's flat
    /// `side_cols` map.
    pub fn side_segment(
        &self,
        col_name: &str,
        suffix: &str,
    ) -> Option<&TrackedSideColOracle<B>> {
        let target = format!("{col_name}{suffix}");
        self.side_cols
            .iter()
            .find_map(|(field, side)| (field.name().as_str() == target).then_some(side))
    }

    pub fn data_tracked_oracles_indices(&self) -> Vec<usize> {
        self.tracked_oracles
            .iter()
            .enumerate()
            .filter_map(|(idx, (field, _))| (!crate::is_system_column(field.name())).then_some(idx))
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
        if self.tracked_oracles.is_empty() {
            return "TrackedTableOracle<empty>".to_string();
        }

        let headers: Vec<String> = self
            .tracked_oracles
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

    /// Folds the specified column oracles of the tracked table oracle using the
    /// provided challenges and returns the resulting folded tracked column
    /// oracle. The output tracked column will have the same activator
    /// polynomial as the original tracked table oracle (if any) and does
    /// not have any datatype
    pub fn fold(&self, col_inds: &[usize], challs: &[B::F]) -> TrackedColOracle<B> {
        let first_idx = *col_inds
            .first()
            .expect("fold requires at least one column index");
        let (_, first_oracle) = self
            .tracked_oracles
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
            let (_, col_oracle) = self
                .tracked_oracles
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
    /// Returns the tracked column oracle at the specified index
    pub fn tracked_col_oracle_by_ind(&self, col_ind: usize) -> TrackedColOracle<B> {
        let (field_ref, data_tracked_oracle) = self
            .tracked_oracles
            .iter()
            .nth(col_ind)
            .expect("column oracle not found");

        TrackedColOracle::new(
            data_tracked_oracle.clone(),
            self.activator_tracked_poly(),
            Some(field_ref.clone()),
        )
    }

    /// Returns the tracked column oracle with the specified name, fully
    /// grouped with its aux row-domain segments and side-domain segments
    /// (via the `tracked_col_oracles` bridge). Returns `None` if `name`
    /// is not a source-column name in this table oracle.
    pub fn tracked_col_oracle_by_name(&self, name: &str) -> Option<TrackedColOracle<B>> {
        self.tracked_col_oracles()
            .iter()
            .find_map(|(f, c)| (f.name() == name).then(|| c.clone()))
    }

    /// Returns the tracked column oracles at the specified indices
    pub fn tracked_col_oracles_by_indices(&self, indices: &[usize]) -> Vec<TrackedColOracle<B>> {
        indices
            .iter()
            .map(|&i| self.tracked_col_oracle_by_ind(i))
            .collect()
    }

    /// Returns a subtable oracle containing the tracked column oracles at the
    /// specified indices and the current table oracle's activator column (if
    /// any).
    pub fn tracked_subtable_by_indices(&self, indices: &[usize]) -> TrackedTableOracle<B> {
        let mut sub_oracles = IndexMap::with_capacity(
            indices.len() + self.activator_tracked_poly().is_some() as usize,
        );

        for &idx in indices {
            let (field_ref, tracked_oracle) = self
                .tracked_oracles
                .get_index(idx)
                .expect("column oracle index out of bounds");
            sub_oracles.insert(field_ref.clone(), tracked_oracle.clone());
        }

        for (field_ref, tracked_oracle) in self.tracked_oracles.iter() {
            if crate::is_system_column(field_ref.name()) {
                sub_oracles
                    .entry(field_ref.clone())
                    .or_insert_with(|| tracked_oracle.clone());
            }
        }

        let sub_schema = self.schema.as_ref().map(|schema| {
            let fields = sub_oracles
                .keys()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<Field>>();
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });

        let retained_base_names: Vec<String> = sub_oracles
            .keys()
            .filter(|f| !crate::is_system_column(f.name()))
            .map(|f| f.name().to_string())
            .collect();
        let mut sub_side_cols: IndexMap<FieldRef, TrackedSideColOracle<B>> = IndexMap::new();
        for (side_field, side_col) in self.side_cols.iter() {
            if retained_base_names
                .iter()
                .any(|base| crate::encoding::is_segment_of(side_field.name(), base))
            {
                sub_side_cols.insert(side_field.clone(), side_col.clone());
            }
        }

        TrackedTableOracle::new_with_side_cols(sub_schema, sub_oracles, self.log_size, sub_side_cols)
    }
    /// Returns all the tracked column oracles in the table, including the
    /// activator column (if any)
    pub fn all_tracked_col_oracles(&self) -> Vec<TrackedColOracle<B>> {
        self.tracked_col_oracles_by_indices(
            &(0..self.num_total_tracked_col_oracles()).collect::<Vec<usize>>(),
        )
    }

    /// Number of columns in the table including activator (if any)
    pub fn num_total_tracked_col_oracles(&self) -> usize {
        self.tracked_oracles.len()
    }
    /// Returns the number of columns in the table excluding activator (if any)
    pub fn num_data_tracked_col_oracles(&self) -> usize {
        self.tracked_oracles
            .keys()
            .filter(|field| !crate::is_system_column(field.name()))
            .count()
    }

    /// Returns the tracked oracle of the activator column, if any
    pub fn activator_tracked_poly(&self) -> Option<TrackedOracle<B>> {
        self.tracked_oracles.iter().find_map(|(field, oracle)| {
            (field.name() == ACTIVATOR_COL_NAME).then(|| oracle.clone())
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
                        activator: side.activator.commitment(),
                        log_size: side.log_size,
                        active_len: side.active_len,
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
