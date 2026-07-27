use std::{fmt, sync::Arc};

use ark_ff::{PrimeField, Zero};

use crate::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, col::TrackedCol,
    table_oracle::CONSTRAINTS_SUMMARY_METADATA_KEY,
};
use ark_piop::SnarkBackend;
#[cfg(debug_assertions)]
use ark_piop::errors::SnarkResult;
use ark_piop::{
    arithmetic::mat_poly::mle::MLE,
    piop::DeepClone,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use derivative::Derivative;
use indexmap::IndexMap;
use serde_json::{Value, from_slice as schema_from_slice, to_vec as schema_to_vec};
/// A tracked side-domain column carried alongside (but not inside) the
/// row-uniform `TrackedTable`. Each side column has its own multilinear
/// domain. The contiguous-one activator is fully described by `active_len`
/// (and rebuilt on demand at commit/track time) so no separate tracked
/// activator handle is kept here.
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
pub struct TrackedSideCol<B: SnarkBackend> {
    pub data: TrackedPoly<B>,
    pub activator: TrackedPoly<B>,
    pub log_size: usize,
    pub active_len: usize,
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedSideCol<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedSideCol")
            .field("log_size", &self.log_size)
            .field("active_len", &self.active_len)
            .finish()
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// An abstraction of a tracked arithmetized table in dbSNARK
/// A tracked arithmetized table is represented by a set of tracked polynomials
/// representing the columns
pub struct TrackedTable<B: SnarkBackend> {
    /// The schema of the table, if any
    schema: Option<Schema>,
    /// The polynomials representing the columns, stored in schema order
    tracked_polys: IndexMap<FieldRef, TrackedPoly<B>>,
    /// The log size of the table
    log_size: usize,
    /// Side-domain tracked polynomials owned by this table. Keyed by the
    /// side segment's field reference (e.g. `<col>__chars`). Subtable
    /// operations propagate the side cols of any retained data column.
    side_cols: IndexMap<FieldRef, TrackedSideCol<B>>,
}

impl<B: SnarkBackend> Default for TrackedTable<B> {
    fn default() -> Self {
        Self {
            schema: None,
            tracked_polys: IndexMap::new(),
            log_size: 0,
            side_cols: IndexMap::new(),
        }
    }
}

impl<B: SnarkBackend> core::fmt::Debug for TrackedTable<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedTable")
            .field("num_total_cols", &self.num_total_tracked_cols())
            .field("num_data_cols", &self.num_data_tracked_cols())
            .field("log_size", &self.log_size())
            .field("degrees", &self.degrees())
            .finish()
    }
}

impl<B: SnarkBackend> DeepClone<B> for TrackedTable<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        let tracked_polys = self
            .tracked_polys
            .iter()
            .map(|(field, poly)| (field.clone(), poly.deep_clone(prover.clone())))
            .collect::<IndexMap<_, _>>();
        let side_cols = self
            .side_cols
            .iter()
            .map(|(field, side)| {
                (
                    field.clone(),
                    TrackedSideCol {
                        data: side.data.deep_clone(prover.clone()),
                        activator: side.activator.deep_clone(prover.clone()),
                        log_size: side.log_size,
                        active_len: side.active_len,
                    },
                )
            })
            .collect::<IndexMap<_, _>>();
        Self::new_with_side_cols(self.schema.clone(), tracked_polys, self.log_size, side_cols)
    }
}

impl<B: SnarkBackend> fmt::Display for TrackedTable<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.tracked_polys.is_empty() {
            write!(f, "TrackedTable empty")
        } else {
            let cols: Vec<String> = self
                .tracked_polys
                .keys()
                .map(|field| field.name().to_string())
                .collect();
            write!(
                f,
                "TrackedTable cols=({}), log_size={}, active={}, degrees={:?}, constraints={}",
                cols.join(","),
                self.log_size,
                self.active_row_count(),
                self.degrees(),
                constraints_summary_label(self.schema_ref()).unwrap_or_else(|| "none".to_string())
            )
        }
    }
}

impl<B: SnarkBackend> TrackedTable<B> {
    /// Constructs a single-column table and optionally appends an activator column.
    pub fn single_column_with_activator(
        field: FieldRef,
        data_poly: TrackedPoly<B>,
        activator: Option<TrackedPoly<B>>,
    ) -> Self {
        let log_size = data_poly.log_size();
        let mut polys = IndexMap::new();
        polys.insert(field, data_poly);
        if let Some(activator_poly) = activator {
            polys.insert(ACTIVATOR_FIELD.clone(), activator_poly);
        }
        TrackedTable::new(None, polys, log_size)
    }

    /// Constructs a new `TrackedTable` from the provided schema (if any),
    /// tracked polynomials, and log size of the table. The table starts
    /// with no side-domain columns.
    pub fn new(
        schema: Option<Schema>,
        tracked_polys: IndexMap<FieldRef, TrackedPoly<B>>,
        log_size: usize,
    ) -> Self {
        Self::new_with_side_cols(schema, tracked_polys, log_size, IndexMap::new())
    }

    /// Constructs a new `TrackedTable` with explicit side-domain columns.
    pub fn new_with_side_cols(
        schema: Option<Schema>,
        tracked_polys: IndexMap<FieldRef, TrackedPoly<B>>,
        log_size: usize,
        side_cols: IndexMap<FieldRef, TrackedSideCol<B>>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&schema, &tracked_polys, log_size).unwrap();
        }

        Self {
            schema,
            tracked_polys,
            log_size,
            side_cols,
        }
    }

    /// Read-only access to this table's side-domain columns.
    pub fn side_cols(&self) -> &IndexMap<FieldRef, TrackedSideCol<B>> {
        &self.side_cols
    }

    /// Insert (or replace) a side-domain column on this table.
    pub fn insert_side_col(&mut self, field: FieldRef, side: TrackedSideCol<B>) {
        self.side_cols.insert(field, side);
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        schema: &Option<Schema>,
        tracked_polys: &IndexMap<FieldRef, TrackedPoly<B>>,
        log_size: usize,
    ) -> SnarkResult<()> {
        // All columns have the same tracker
        let first_poly = tracked_polys
            .values()
            .next()
            .expect("table should have at least one column");
        tracked_polys.values().for_each(|poly| {
            assert!(
                first_poly.same_tracker(poly),
                "All columns must share the same tracker"
            );
        });

        // All columns must have the same log size as the table
        tracked_polys.values().for_each(|poly| {
            assert_eq!(
                poly.log_size(),
                log_size,
                "All columns must have the same log size as the table"
            );
        });

        // If schema is provided, it must match the fields of the tracked polynomials
        if let Some(schema) = &schema {
            schema
                .fields()
                .iter()
                .zip(tracked_polys.keys())
                .for_each(|(f1, f2)| {
                    assert_eq!(
                        f1, f2,
                        "Schema fields must match the tracked polynomial fields"
                    );
                });
        }

        Ok(())
    }

    /// Returns the tracked polynomials representing the columns of the table
    pub fn tracked_polys(&self) -> IndexMap<FieldRef, TrackedPoly<B>> {
        self.tracked_polys.clone()
    }

    pub fn tracked_polys_iter(&self) -> impl Iterator<Item = (&FieldRef, &TrackedPoly<B>)> {
        self.tracked_polys.iter()
    }

    pub fn data_tracked_polys_indices(&self) -> Vec<usize> {
        self.tracked_polys
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

    /// Folds the specified columns of the tracked table using the provided
    /// challenges and returns the resulting folded tracked column. The
    /// output tracked column will have the same activator polynomial as the
    /// original table (if any) and does not have any datatype
    pub fn fold(&self, col_inds: &[usize], challs: &[B::F]) -> TrackedCol<B> {
        let first_idx = *col_inds
            .first()
            .expect("fold requires at least one column index");
        let (_, first_poly) = self
            .tracked_polys
            .get_index(first_idx)
            .expect("column index out of bounds");
        if col_inds.len() == 1 {
            return TrackedCol::new(first_poly.clone(), self.activator_tracked_poly(), None);
        }

        debug_assert_eq!(col_inds.len(), challs.len());
        let first_chall = challs
            .first()
            .copied()
            .expect("fold requires at least one challenge");
        let mut folded: TrackedPoly<B> = first_poly.mul_scalar_poly(first_chall);
        for (&col_idx, &chall) in col_inds.iter().zip(challs).skip(1) {
            let (_, poly) = self
                .tracked_polys
                .get_index(col_idx)
                .expect("column index out of bounds");
            let term = poly.mul_scalar_poly(chall);
            folded += &term;
        }
        TrackedCol::new(folded, self.activator_tracked_poly(), None)
    }
    /// Folds all the data (i.e. excluding the activator column) tracked column
    /// polynomials
    pub fn fold_all_data_columns(&self, challs: &[B::F]) -> TrackedCol<B> {
        let data_col_indices = self.data_tracked_polys_indices();
        self.fold(&data_col_indices, challs)
    }

    /// Returns the tracked column at the specified index
    pub fn tracked_col_by_ind(&self, ind: usize) -> TrackedCol<B> {
        let (field_ref, data_tracked_poly) = self
            .tracked_polys
            .get_index(ind)
            .expect("column index out of bounds");
        TrackedCol::new(
            data_tracked_poly.clone(),
            self.activator_tracked_poly(),
            Some(field_ref.clone()),
        )
    }
    /// Returns the tracked column with the specified name
    pub fn tracked_col_by_name(&self, name: &str) -> Option<TrackedCol<B>> {
        let idx = self
            .schema
            .as_ref()
            .and_then(|schema| schema.index_of(name).ok())?;
        Some(self.tracked_col_by_ind(idx))
    }

    /// Returns the tracked columns at the specified indices
    pub fn tracked_col_by_indices(&self, indices: &[usize]) -> Vec<TrackedCol<B>> {
        indices
            .iter()
            .map(|&i| self.tracked_col_by_ind(i))
            .collect()
    }

    pub fn degrees(&self) -> Vec<usize> {
        self.tracked_polys
            .values()
            .map(|poly| poly.degree())
            .collect()
    }

    /// Renames the column at the given index, updating both the field reference
    /// keys and the stored schema (when present).
    pub fn rename_col(&mut self, idx: usize, new_name: &str) {
        assert!(idx < self.tracked_polys.len(), "column index out of bounds");

        // Build the new field reference using the existing field's properties.
        let old_field = self
            .tracked_polys
            .get_index(idx)
            .map(|(f, _)| f.clone())
            .expect("column index out of bounds");
        let new_field_ref = Arc::new(
            Field::new(
                new_name,
                old_field.data_type().clone(),
                old_field.is_nullable(),
            )
            .with_metadata(old_field.metadata().clone()),
        );

        // Rebuild the tracked_polys map to preserve ordering.
        let mut new_polys = IndexMap::with_capacity(self.tracked_polys.len());
        for (i, (field, poly)) in self.tracked_polys.clone().into_iter().enumerate() {
            if i == idx {
                new_polys.insert(new_field_ref.clone(), poly);
            } else {
                new_polys.insert(field, poly);
            }
        }
        self.tracked_polys = new_polys;

        // Update schema if present.
        if let Some(schema) = &self.schema {
            let metadata = schema.metadata().clone();
            let mut fields = schema
                .fields()
                .iter()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>();
            fields[idx] = new_field_ref.as_ref().clone();
            self.schema = Some(Schema::new_with_metadata(fields, metadata));
        }
    }

    /// Returns a subtable containing the tracked columns at the specified
    /// indices and the current table's activator column (if any).
    /// Side-domain columns owned by retained data columns are carried over
    /// (identified by `is_segment_of(side_field.name(), retained_col.name())`).
    pub fn tracked_subtable_by_indices(&self, indices: &[usize]) -> TrackedTable<B> {
        let mut sub_polys = IndexMap::with_capacity(
            indices.len() + self.activator_tracked_poly().is_some() as usize,
        );

        for &idx in indices {
            let (field_ref, tracked_poly) = self
                .tracked_polys
                .get_index(idx)
                .expect("column index out of bounds");
            sub_polys.insert(field_ref.clone(), tracked_poly.clone());
        }

        for (field_ref, tracked_poly) in self.tracked_polys.iter() {
            if crate::is_system_column(field_ref.name()) {
                sub_polys
                    .entry(field_ref.clone())
                    .or_insert_with(|| tracked_poly.clone());
            }
        }

        let sub_schema = self.schema.as_ref().map(|schema| {
            let fields = sub_polys
                .keys()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<Field>>();
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });

        let retained_base_names: Vec<String> = sub_polys
            .keys()
            .filter(|f| !crate::is_system_column(f.name()))
            .map(|f| f.name().to_string())
            .collect();
        let mut sub_side_cols: IndexMap<FieldRef, TrackedSideCol<B>> = IndexMap::new();
        for (side_field, side_col) in self.side_cols.iter() {
            if retained_base_names
                .iter()
                .any(|base| crate::encoding::is_segment_of(side_field.name(), base))
            {
                sub_side_cols.insert(side_field.clone(), side_col.clone());
            }
        }

        TrackedTable::new_with_side_cols(sub_schema, sub_polys, self.log_size, sub_side_cols)
    }

    /// Returns all the tracked column polynomials in the table, including the
    /// activator column (if any)
    pub fn all_tracked_cols(&self) -> Vec<TrackedCol<B>> {
        self.tracked_col_by_indices(&(0..self.num_total_tracked_cols()).collect::<Vec<usize>>())
    }

    // Number of data columns including  activator (if any)
    pub fn num_total_tracked_cols(&self) -> usize {
        self.tracked_polys.len()
    }

    // Number of data columns excluding system columns (activator/row_id).
    pub fn num_data_tracked_cols(&self) -> usize {
        self.tracked_polys
            .keys()
            .filter(|field| !crate::is_system_column(field.name()))
            .count()
    }

    /// Returns the tracked polynomial of the activator column, if any
    pub fn activator_tracked_poly(&self) -> Option<TrackedPoly<B>> {
        self.tracked_polys
            .iter()
            .find_map(|(field, poly)| (field.name() == ACTIVATOR_COL_NAME).then(|| poly.clone()))
    }

    /// Pretty-print the tracked table in a row/column layout similar to
    /// DataFusion's RecordBatch formatter.
    pub fn pretty_string(&self) -> String {
        if self.tracked_polys.is_empty() {
            return "TrackedTable<empty>".to_string();
        }

        let mut headers = Vec::with_capacity(self.tracked_polys.len() + 1);
        let mut columns: Vec<Vec<String>> = Vec::with_capacity(self.tracked_polys.len() + 1);

        for (field, poly) in self.tracked_polys.iter() {
            let header = {
                let name = field.name();
                if name.is_empty() {
                    "-".to_string()
                } else {
                    name.to_string()
                }
            };
            headers.push(header);
            let values = poly
                .evaluations()
                .into_iter()
                .map(|val| abbreviate_field_value(&format!("{}", val)))
                .collect::<Vec<_>>();
            columns.push(values);
        }

        let num_rows = columns.first().map(|c| c.len()).unwrap_or(0);
        let row_numbers = (0..num_rows).map(|idx| idx.to_string()).collect::<Vec<_>>();
        headers.insert(0, "row# (display)".to_string());
        columns.insert(0, row_numbers);
        let widths: Vec<usize> = headers
            .iter()
            .enumerate()
            .map(|(idx, header)| {
                let col_width = columns[idx].iter().map(|val| val.len()).max().unwrap_or(0);
                std::cmp::max(header.len(), col_width)
            })
            .collect();

        let mut out = String::new();
        out.push_str(&border_line(&widths));
        out.push_str(&row_line(&headers, &widths));
        out.push_str(&border_line(&widths));

        for row_idx in 0..num_rows {
            let row_values: Vec<String> = columns
                .iter()
                .map(|col| col.get(row_idx).cloned().unwrap_or_else(|| "-".to_string()))
                .collect();
            out.push_str(&row_line(&row_values, &widths));
        }

        out.push_str(&border_line(&widths));
        out
    }

    pub fn active_row_count(&self) -> usize {
        self.activator_tracked_poly()
            .map(|poly| poly.evaluations().iter().filter(|v| !v.is_zero()).count())
            .unwrap_or_else(|| self.size())
    }
}

/// A side-domain polynomial that lives **outside** the row-uniform table.
/// Carries its own `log_size` (generally different from the owning table's)
/// and a contiguous-one activator that is fully described by `active_len`.
/// Used for the per-string-column char-level polynomials from paper §3.2
/// (`__chars`, `__orig_ind`, `__int_ind`, `__bnd`).
///
/// The data poly is stored in its narrowest native form (bytes for chars/bnd,
/// u32 for orig_ind/int_ind) so it stays much smaller than the field-element
/// form. Commit and tracking passes materialize transient `MLE<F>` views from
/// this raw data (and from `active_len` for the activator) only at the moment
/// of MSM / proof-binding, then drop them.
#[derive(Clone, Debug, PartialEq)]
pub struct ArithSideCol {
    /// Element-type-tagged raw values, pow2-padded with zeros.
    /// `data.len()` == `1 << log_size`.
    pub data: crate::encoding::SideColData,
    /// Number of variables in the side-domain MLE (data and activator
    /// share this).
    pub log_size: usize,
    /// Number of active (non-padding) leading entries. Fully describes the
    /// contiguous-one activator polynomial.
    pub active_len: usize,
}

#[derive(Clone, Debug, PartialEq)]
/// An abstraction of an arithmetized table in dbSNARK
/// An arithmetic table might not be tracked and can be serialized and
/// deserialized
pub struct ArithTable<F: PrimeField> {
    schema: Option<Schema>,
    polynomials: IndexMap<FieldRef, Arc<MLE<F>>>,
    log_size: usize,
    /// Side-domain polynomials owned by this table, keyed by the side
    /// segment's own field reference (e.g. the `FieldRef` for
    /// `<col>__chars`). Each side column carries its own `log_size` and
    /// activator and is committed separately from the row-domain
    /// `polynomials`.
    side_cols: IndexMap<FieldRef, ArithSideCol>,
}
impl<F: PrimeField> std::fmt::Display for ArithTable<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.polynomials.is_empty() {
            write!(f, "ArithTable empty")
        } else {
            let cols: Vec<String> = self
                .polynomials
                .keys()
                .map(|field| field.name().to_string())
                .collect();
            write!(
                f,
                "ArithTable cols=({}), log_size={}, active={}, constraints={}",
                cols.join(","),
                self.log_size,
                self.active_row_count(),
                constraints_summary_label(self.schema.as_ref())
                    .unwrap_or_else(|| "none".to_string())
            )
        }
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

impl<F: PrimeField> ArithTable<F> {
    /// Constructs a new `ArithTable` with no side-domain columns.
    pub fn new(
        schema: Option<Schema>,
        polynomials: IndexMap<FieldRef, Arc<MLE<F>>>,
        log_size: usize,
    ) -> Self {
        Self::new_with_side_cols(schema, polynomials, log_size, IndexMap::new())
    }

    /// Constructs a new `ArithTable`, optionally seeded with side-domain
    /// columns (e.g. per-string-column concatenated `__chars` polys).
    pub fn new_with_side_cols(
        schema: Option<Schema>,
        polynomials: IndexMap<FieldRef, Arc<MLE<F>>>,
        log_size: usize,
        side_cols: IndexMap<FieldRef, ArithSideCol>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&schema, &polynomials, log_size).unwrap();
        }

        Self {
            schema,
            polynomials,
            log_size,
            side_cols,
        }
    }

    /// Read-only access to this table's side-domain columns, keyed by side
    /// segment field reference (e.g. `<col>__chars`).
    pub fn side_cols(&self) -> &IndexMap<FieldRef, ArithSideCol> {
        &self.side_cols
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        schema: &Option<Schema>,
        polys: &IndexMap<FieldRef, Arc<MLE<F>>>,
        log_size: usize,
    ) -> SnarkResult<()> {
        // All columns must have the same log size as the table
        polys.values().for_each(|poly| {
            assert_eq!(
                poly.num_vars(),
                log_size,
                "All columns must have the same log size as the table"
            );
        });

        // If schema is provided, it must match the fields of the tracked polynomials
        if let Some(schema) = &schema {
            schema
                .fields()
                .iter()
                .zip(polys.keys())
                .for_each(|(f1, f2)| {
                    assert_eq!(
                        f1, f2,
                        "Schema fields must match the tracked polynomial fields"
                    );
                });
        }

        Ok(())
    }

    /// Returns the polynomials representing the columns of the table
    pub fn polynomials(&self) -> &IndexMap<FieldRef, Arc<MLE<F>>> {
        &self.polynomials
    }

    /// Returns the log size of the table
    pub fn log_size(&self) -> usize {
        self.log_size
    }

    /// Returns the size of the table
    pub fn size(&self) -> usize {
        1 << self.log_size()
    }

    pub fn active_row_count(&self) -> usize {
        self.polynomials
            .iter()
            .find_map(|(field, poly)| {
                (field.name() == ACTIVATOR_COL_NAME)
                    .then(|| poly.evaluations().iter().filter(|v| !v.is_zero()).count())
            })
            .unwrap_or_else(|| self.size())
    }

    /// Number of columns in the table including activator (if any)
    pub fn num_total_cols(&self) -> usize {
        self.polynomials.len()
    }

    /// Returns the optional schema of the table
    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    /// Constructs an `ArithTable` from a `TrackedTable` by extracting
    /// the underlying MLE evaluations of both row-domain and side-domain
    /// columns.
    pub fn from_tracked_table<B>(table: &TrackedTable<B>) -> ArithTable<B::F>
    where
        B: SnarkBackend,
    {
        let schema = table.schema();
        let size = table.size();
        let tracked_polys = table
            .tracked_polys
            .iter()
            .map(|(field, poly)| {
                let evals = poly.evaluations();
                let mle = Arc::new(MLE::from_evaluations_slice(poly.log_size(), &evals));
                (field.clone(), mle)
            })
            .collect::<IndexMap<_, _>>();
        // Side cols on the TrackedTable side hold `TrackedPoly<B>` handles;
        // demoting them back to raw byte / u32 values would require
        // knowing each column's original element type by suffix. Since
        // this conversion has no live callers today, we drop side cols
        // for now. If a caller needs the round-trip, extend this to
        // recover the element type from the segment suffix
        // (`__chars`, `__bnd` → Bytes; `__orig_ind`, `__int_ind` → U32).
        let side_cols: IndexMap<FieldRef, ArithSideCol> = IndexMap::new();
        let _ = table.side_cols.iter(); // touch to keep it live if reactivated
        ArithTable::new_with_side_cols(schema, tracked_polys, size, side_cols)
    }

    /// Returns the polynomial of the activator polynomial, if any
    pub fn activator_polynomial(&self) -> Option<&Arc<MLE<F>>> {
        self.polynomials
            .iter()
            .find_map(|(field, poly)| (field.name() == ACTIVATOR_COL_NAME).then_some(poly))
    }
}

impl<B: SnarkBackend> From<TrackedTable<B>> for ArithTable<B::F> {
    fn from(table: TrackedTable<B>) -> Self {
        Self::from_tracked_table(&table)
    }
}

impl<F: PrimeField> CanonicalSerialize for ArithTable<F> {
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

        (self.polynomials.len() as u64).serialize_with_mode(&mut writer, compress)?;

        for (field_ref, mle) in &self.polynomials {
            let field_bytes = serde_json::to_vec(field_ref.as_ref())
                .map_err(|_| SerializationError::InvalidData)?;
            field_bytes.serialize_with_mode(&mut writer, compress)?;

            (mle.num_vars() as u64).serialize_with_mode(&mut writer, compress)?;

            let evaluations = mle.evaluations();
            (evaluations.len() as u64).serialize_with_mode(&mut writer, compress)?;
            for value in evaluations {
                value.serialize_with_mode(&mut writer, compress)?;
            }
        }

        (self.size() as u64).serialize_with_mode(&mut writer, compress)?;

        // Side-domain columns: serialized after the row-uniform polynomials
        // as (log_size, active_len, data_bytes). The activator is fully
        // described by active_len (contiguous-ones), so nothing else needs
        // to be persisted for it.
        (self.side_cols.len() as u64).serialize_with_mode(&mut writer, compress)?;
        for (field_ref, side) in &self.side_cols {
            let field_bytes = serde_json::to_vec(field_ref.as_ref())
                .map_err(|_| SerializationError::InvalidData)?;
            field_bytes.serialize_with_mode(&mut writer, compress)?;
            (side.log_size as u64).serialize_with_mode(&mut writer, compress)?;
            (side.active_len as u64).serialize_with_mode(&mut writer, compress)?;
            // Element-type tag: 0 = Bytes, 1 = U32. New tags append.
            match &side.data {
                crate::encoding::SideColData::Bytes(bytes) => {
                    0u8.serialize_with_mode(&mut writer, compress)?;
                    bytes.serialize_with_mode(&mut writer, compress)?;
                }
                crate::encoding::SideColData::U32(vals) => {
                    1u8.serialize_with_mode(&mut writer, compress)?;
                    vals.serialize_with_mode(&mut writer, compress)?;
                }
            }
        }
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut size = self.schema.is_some().serialized_size(compress);

        if let Some(schema) = &self.schema {
            let schema_bytes = schema_to_vec(schema).expect("schema serialization should succeed");
            size += schema_bytes.serialized_size(compress);
        }

        size += (self.polynomials.len() as u64).serialized_size(compress);
        for (field_ref, mle) in &self.polynomials {
            let field_bytes =
                serde_json::to_vec(field_ref.as_ref()).expect("field serialization should succeed");
            size += field_bytes.serialized_size(compress);
            size += (mle.num_vars() as u64).serialized_size(compress);
            let evaluations = mle.evaluations();
            size += (evaluations.len() as u64).serialized_size(compress);
            for value in evaluations {
                size += value.serialized_size(compress);
            }
        }

        size += (self.size() as u64).serialized_size(compress);

        size += (self.side_cols.len() as u64).serialized_size(compress);
        for (field_ref, side) in &self.side_cols {
            let field_bytes =
                serde_json::to_vec(field_ref.as_ref()).expect("field serialization should succeed");
            size += field_bytes.serialized_size(compress);
            size += (side.log_size as u64).serialized_size(compress);
            size += (side.active_len as u64).serialized_size(compress);
            size += 0u8.serialized_size(compress); // element-type tag
            size += match &side.data {
                crate::encoding::SideColData::Bytes(bytes) => bytes.serialized_size(compress),
                crate::encoding::SideColData::U32(vals) => vals.serialized_size(compress),
            };
        }
        size
    }
}

impl<F: PrimeField> CanonicalDeserialize for ArithTable<F> {
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

        let column_count = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let column_count =
            usize::try_from(column_count).map_err(|_| SerializationError::InvalidData)?;

        let mut polynomials = IndexMap::with_capacity(column_count);
        for _ in 0..column_count {
            let field_bytes = Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
            let field: Field = serde_json::from_slice(&field_bytes)
                .map_err(|_| SerializationError::InvalidData)?;
            let field_ref = Arc::new(field);

            let nv_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
            let nv = usize::try_from(nv_raw).map_err(|_| SerializationError::InvalidData)?;

            let len_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
            let len = usize::try_from(len_raw).map_err(|_| SerializationError::InvalidData)?;
            if len != (1usize << nv) {
                return Err(SerializationError::InvalidData);
            }

            let mut evaluations = Vec::with_capacity(len);
            for _ in 0..len {
                let value = F::deserialize_with_mode(&mut reader, compress, validate)?;
                evaluations.push(value);
            }
            let mle = Arc::new(MLE::from_evaluations_vec(nv, evaluations));
            polynomials.insert(field_ref, mle);
        }

        let size_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let size = usize::try_from(size_raw).map_err(|_| SerializationError::InvalidData)?;

        // Side-domain columns: appended after the row-uniform table data.
        // The count, each field, then (data, activator) MLE pair per side col.
        let side_count_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let side_count =
            usize::try_from(side_count_raw).map_err(|_| SerializationError::InvalidData)?;
        let mut side_cols = IndexMap::with_capacity(side_count);
        for _ in 0..side_count {
            let field_bytes = Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
            let field: Field = serde_json::from_slice(&field_bytes)
                .map_err(|_| SerializationError::InvalidData)?;
            let field_ref = Arc::new(field);

            let log_size_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
            let log_size =
                usize::try_from(log_size_raw).map_err(|_| SerializationError::InvalidData)?;
            let active_len_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
            let active_len =
                usize::try_from(active_len_raw).map_err(|_| SerializationError::InvalidData)?;

            // Element-type tag: 0 = Bytes, 1 = U32.
            let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
            let data = match tag {
                0 => {
                    let bytes =
                        Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
                    if bytes.len() != (1usize << log_size) {
                        return Err(SerializationError::InvalidData);
                    }
                    crate::encoding::SideColData::Bytes(bytes)
                }
                1 => {
                    let vals =
                        Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
                    if vals.len() != (1usize << log_size) {
                        return Err(SerializationError::InvalidData);
                    }
                    crate::encoding::SideColData::U32(vals)
                }
                _ => return Err(SerializationError::InvalidData),
            };

            side_cols.insert(
                field_ref,
                ArithSideCol {
                    data,
                    log_size,
                    active_len,
                },
            );
        }

        let table = Self::new_with_side_cols(schema, polynomials, size, side_cols);
        table.check()?;
        Ok(table)
    }
}

impl<F: PrimeField> Valid for ArithTable<F> {
    fn check(&self) -> Result<(), SerializationError> {
        if let Some(schema) = &self.schema
            && schema.fields().len() != self.polynomials.len()
        {
            return Err(SerializationError::InvalidData);
        }

        for (_, mle) in &self.polynomials {
            if self.size() != 0 && (1usize << mle.num_vars()) != self.size() {
                return Err(SerializationError::InvalidData);
            }
        }
        Ok(())
    }
}
