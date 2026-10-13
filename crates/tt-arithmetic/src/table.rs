use std::{fmt, sync::Arc};

use ark_ff::{PrimeField, Zero};

use crate::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD,
    col::{PolyBundle, TrackedCol},
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
#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""))]
/// A tracked arithmetized table: the tracked polynomials of its columns.
///
/// Storage is keyed by source column. The flat view
/// ([`Self::tracked_polys`]) lists every row-domain segment as its own
/// field, in source-column order; column indices in this API refer to it.
pub struct TrackedTable<B: SnarkBackend> {
    /// Lists the flat Arrow fields (primaries and expanded segments).
    schema: Option<Schema>,
    /// Keyed by source column, in schema order. Each `TrackedCol` owns its
    /// primary, row-domain aux and side-domain polynomials.
    tracked_cols: IndexMap<FieldRef, TrackedCol<B>>,
    log_size: usize,
}

impl<B: SnarkBackend> Default for TrackedTable<B> {
    fn default() -> Self {
        Self {
            schema: None,
            tracked_cols: IndexMap::new(),
            log_size: 0,
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
        let tracked_cols = self
            .tracked_cols
            .iter()
            .map(|(field, col)| (field.clone(), col.deep_clone(prover.clone())))
            .collect::<IndexMap<_, _>>();
        Self {
            schema: self.schema.clone(),
            tracked_cols,
            log_size: self.log_size,
        }
    }
}

impl<B: SnarkBackend> fmt::Display for TrackedTable<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.tracked_cols.is_empty() {
            write!(f, "TrackedTable empty")
        } else {
            let cols: Vec<String> = self
                .tracked_cols
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

    /// A table from the flat schema-order map of row-domain polynomials,
    /// regrouped by source column with `segment_base_name`.
    pub fn new(
        schema: Option<Schema>,
        tracked_polys: IndexMap<FieldRef, TrackedPoly<B>>,
        log_size: usize,
    ) -> Self {
        Self::new_with_side_cols(schema, tracked_polys, log_size, IndexMap::new())
    }

    /// [`Self::new`] with side-domain segments, each attached to its source
    /// column.
    pub fn new_with_side_cols(
        schema: Option<Schema>,
        tracked_polys: IndexMap<FieldRef, TrackedPoly<B>>,
        log_size: usize,
        side_cols: IndexMap<FieldRef, PolyBundle<B>>,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&schema, &tracked_polys, log_size).unwrap();
        }
        let tracked_cols = regroup_flat_into_tracked_cols(&tracked_polys, &side_cols);
        Self {
            schema,
            tracked_cols,
            log_size,
        }
    }

    /// A table from columns already grouped by source column.
    pub fn new_from_cols(
        schema: Option<Schema>,
        tracked_cols: IndexMap<FieldRef, TrackedCol<B>>,
        log_size: usize,
    ) -> Self {
        Self {
            schema,
            tracked_cols,
            log_size,
        }
    }

    /// The side-domain segments, keyed by a field named `<col><suffix>`
    /// (`<col>__chars`) that carries the source column's metadata (e.g.
    /// `tt.qualifier`).
    pub fn side_cols(&self) -> IndexMap<FieldRef, crate::col::PolyBundle<B>> {
        let mut out: IndexMap<FieldRef, crate::col::PolyBundle<B>> = IndexMap::new();
        for (field, col) in self.tracked_cols.iter() {
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

    /// Attach a side-domain segment to the source column its name points
    /// to (`segment_base_name`), promoting a `SingleSegment` column to
    /// `MultiSegment`.
    pub fn insert_side_col(&mut self, field: FieldRef, side: crate::col::PolyBundle<B>) {
        let base_name = crate::encoding::segment_base_name(field.name())
            .expect("insert_side_col: field name must carry a known segment suffix")
            .to_string();
        let suffix = field.name()[base_name.len()..].to_string();
        let target_field = self
            .tracked_cols
            .keys()
            .find(|f| f.name() == base_name.as_str())
            .cloned()
            .expect("insert_side_col: no source column found for side segment");
        let existing = self
            .tracked_cols
            .swap_remove(&target_field)
            .expect("insert_side_col: source column disappeared");
        let promoted = match existing {
            TrackedCol::SingleSegment {
                poly_bundle,
                field_ref,
            } => TrackedCol::new_multi_split(
                poly_bundle,
                Vec::new(),
                vec![(suffix, side)],
                field_ref,
            ),
            TrackedCol::MultiSegment {
                primary_poly_bundle,
                mut aux_poly_bundles,
                mut side_aux_suffixes,
                field_ref,
            } => {
                aux_poly_bundles.insert(suffix.clone(), side);
                side_aux_suffixes.insert(suffix);
                TrackedCol::MultiSegment {
                    primary_poly_bundle,
                    aux_poly_bundles,
                    side_aux_suffixes,
                    field_ref,
                }
            }
        };
        self.tracked_cols.insert(target_field, promoted);
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        schema: &Option<Schema>,
        tracked_polys: &IndexMap<FieldRef, TrackedPoly<B>>,
        log_size: usize,
    ) -> SnarkResult<()> {
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
        tracked_polys.values().for_each(|poly| {
            if !poly.is_constant() {
                assert_eq!(
                    poly.log_size(),
                    log_size,
                    "All columns must have the same log size as the table"
                );
            }
        });
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

    /// The flat view: every row-domain segment (primaries and row-domain
    /// aux) under its own field, in source-column order.
    pub fn tracked_polys(&self) -> IndexMap<FieldRef, TrackedPoly<B>> {
        let mut out: IndexMap<FieldRef, TrackedPoly<B>> = IndexMap::new();
        for (field, col) in self.tracked_cols.iter() {
            for (suffix, poly, _act) in col.segments_iter() {
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
                out.insert(seg_field, poly.clone());
            }
        }
        out
    }

    /// The flat view as an iterator. The items are owned: the segment
    /// fields are built on demand.
    pub fn tracked_polys_iter(&self) -> Box<dyn Iterator<Item = (FieldRef, TrackedPoly<B>)> + '_> {
        Box::new(self.tracked_cols.iter().flat_map(|(field, col)| {
            col.segments_iter()
                .map(move |(suffix, poly, _act)| {
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
                    (seg_field, poly.clone())
                })
                .collect::<Vec<_>>()
                .into_iter()
        }))
    }

    /// The columns, keyed by source column.
    pub fn tracked_cols(&self) -> IndexMap<FieldRef, TrackedCol<B>> {
        self.tracked_cols.clone()
    }

    pub fn tracked_cols_iter(&self) -> impl Iterator<Item = (&FieldRef, &TrackedCol<B>)> {
        self.tracked_cols.iter()
    }

    /// The side-domain segment `suffix` of source column `col_name`
    /// (`side_segment("n_name", "__chars")`).
    pub fn side_segment(&self, col_name: &str, suffix: &str) -> Option<&PolyBundle<B>> {
        self.tracked_cols
            .iter()
            .find(|(f, _)| f.name() == col_name)
            .and_then(|(_, col)| col.side_segment(suffix))
    }

    /// Flat-view indices of the non-system columns.
    pub fn data_tracked_polys_indices(&self) -> Vec<usize> {
        self.tracked_polys()
            .keys()
            .enumerate()
            .filter_map(|(idx, field)| (!crate::is_system_column(field.name())).then_some(idx))
            .collect()
    }

    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    pub fn schema_ref(&self) -> Option<&Schema> {
        self.schema.as_ref()
    }

    /// Overwrite the schema. For builders that take the field order from
    /// `tracked_polys()` after construction: the tt-core tracking pass does,
    /// so that its schema agrees with the verifier's `all_tracked_cols`
    /// walk in `TrackedTableOracle::from_tracked_table`.
    pub fn set_schema(&mut self, schema: Option<Schema>) {
        self.schema = schema;
    }

    pub fn log_size(&self) -> usize {
        self.log_size
    }

    pub fn size(&self) -> usize {
        1 << self.log_size()
    }

    /// The linear combination of the flat-view columns `col_inds` with the
    /// challenges `challs`; a single column is returned as is.
    pub fn fold(&self, col_inds: &[usize], challs: &[B::F]) -> TrackedCol<B> {
        let flat = self.tracked_polys();
        let first_idx = *col_inds
            .first()
            .expect("fold requires at least one column index");
        let (_, first_poly) = flat
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
            let (_, poly) = flat.get_index(col_idx).expect("column index out of bounds");
            let term = poly.mul_scalar_poly(chall);
            folded += &term;
        }
        TrackedCol::new(folded, self.activator_tracked_poly(), None)
    }

    /// [`Self::fold`] over every non-system column.
    pub fn fold_all_data_columns(&self, challs: &[B::F]) -> TrackedCol<B> {
        let data_col_indices = self.data_tracked_polys_indices();
        self.fold(&data_col_indices, challs)
    }

    /// The flat-view entry `ind` as a `SingleSegment` column with the
    /// table's activator.
    pub fn tracked_col_by_ind(&self, ind: usize) -> TrackedCol<B> {
        let flat = self.tracked_polys();
        let (field_ref, data_tracked_poly) =
            flat.get_index(ind).expect("column index out of bounds");
        TrackedCol::new(
            data_tracked_poly.clone(),
            self.activator_tracked_poly(),
            Some(field_ref.clone()),
        )
    }

    /// The source column `name` with all its segments.
    pub fn tracked_col_by_name(&self, name: &str) -> Option<TrackedCol<B>> {
        self.tracked_cols
            .iter()
            .find_map(|(f, c)| (f.name() == name).then(|| c.clone()))
    }

    pub fn tracked_col_by_indices(&self, indices: &[usize]) -> Vec<TrackedCol<B>> {
        indices
            .iter()
            .map(|&i| self.tracked_col_by_ind(i))
            .collect()
    }

    pub fn degrees(&self) -> Vec<usize> {
        self.tracked_polys()
            .values()
            .map(|poly| poly.degree())
            .collect()
    }

    /// Rename the flat-view entry `idx`. For a primary segment the source
    /// column key is renamed, and its aux segments follow, since their
    /// names derive from it. For an aux segment only the schema entry
    /// changes: no caller renames one.
    pub fn rename_col(&mut self, idx: usize, new_name: &str) {
        let flat = self.tracked_polys();
        assert!(idx < flat.len(), "column index out of bounds");
        let (old_field, _) = flat.get_index(idx).expect("column index out of bounds");
        let old_name = old_field.name().to_string();
        let new_field_ref = Arc::new(
            Field::new(
                new_name,
                old_field.data_type().clone(),
                old_field.is_nullable(),
            )
            .with_metadata(old_field.metadata().clone()),
        );

        let owning_source_col_name: String = self
            .tracked_cols
            .keys()
            .find(|source_field| crate::encoding::is_segment_of(&old_name, source_field.name()))
            .map(|f| f.name().to_string())
            .unwrap_or_else(|| old_name.clone());

        if old_name == owning_source_col_name {
            // A primary: rewrite the source-column key, keeping the order.
            let mut new_cols =
                IndexMap::<FieldRef, TrackedCol<B>>::with_capacity(self.tracked_cols.len());
            let old_source_field = self
                .tracked_cols
                .keys()
                .find(|f| f.name() == owning_source_col_name.as_str())
                .cloned()
                .expect("owning source col field disappeared");
            for (source_field, col) in self.tracked_cols.clone().into_iter() {
                if source_field == old_source_field {
                    new_cols.insert(new_field_ref.clone(), col);
                } else {
                    new_cols.insert(source_field, col);
                }
            }
            self.tracked_cols = new_cols;
        }

        // Find the schema entry by name, not by `idx`: `idx` indexes the
        // flat view, while the schema is set separately (`set_schema`) and
        // may hold only user-visible fields. `__activator__` has a flat
        // entry but no schema field, so the two index spaces differ.
        if let Some(schema) = &self.schema
            && let Some(pos) = schema.fields().iter().position(|f| f.name() == &old_name)
        {
            let metadata = schema.metadata().clone();
            let mut fields = schema
                .fields()
                .iter()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>();
            fields[pos] = new_field_ref.as_ref().clone();
            self.schema = Some(Schema::new_with_metadata(fields, metadata));
        }
    }

    /// The subtable of the source columns that own the flat-view entries
    /// `indices`, with all their segments, plus the system columns.
    pub fn tracked_subtable_by_indices(&self, indices: &[usize]) -> TrackedTable<B> {
        let flat = self.tracked_polys();
        // The source column that owns each flat index. `tracked_polys()`
        // emits each source column's segments consecutively, so a parallel
        // walk recovers it. Retaining by name would be ambiguous: an
        // un-aliased self-join puts two same-named columns in one table
        // (TPC-H Q7's two `nation`s).
        let owners: Vec<FieldRef> = self
            .tracked_cols
            .iter()
            .flat_map(|(field, col)| col.segments_iter().map(move |_| field.clone()))
            .collect();
        let mut retained: indexmap::IndexSet<FieldRef> = indexmap::IndexSet::new();
        if owners.len() == flat.len() {
            for &idx in indices {
                retained.insert(owners.get(idx).expect("column index out of bounds").clone());
            }
        } else {
            // Two segments produced an identical field, so `tracked_polys()`
            // collapsed them and the walk does not line up. Such a table
            // cannot tell its duplicates apart: match on name.
            for &idx in indices {
                let (field, _) = flat.get_index(idx).expect("column index out of bounds");
                let base = crate::encoding::segment_base_name(field.name())
                    .unwrap_or_else(|| field.name());
                for (f, _) in self.tracked_cols.iter() {
                    if f.name() == base {
                        retained.insert(f.clone());
                    }
                }
            }
        }
        for (field, _) in self.tracked_cols.iter() {
            if crate::is_system_column(field.name()) {
                retained.insert(field.clone());
            }
        }

        let mut sub_cols: IndexMap<FieldRef, TrackedCol<B>> = IndexMap::new();
        for (field, col) in self.tracked_cols.iter() {
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
            // Keep a schema field on an exact match, so a retained `n_name`
            // does not bring a same-named sibling's entry. Match on name only
            // where the schema has no duplicate of it: some builders emit
            // schema fields without the primary's metadata.
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

        TrackedTable::new_from_cols(sub_schema, sub_cols, self.log_size)
    }

    /// Every flat-view entry as a `SingleSegment` column.
    pub fn all_tracked_cols(&self) -> Vec<TrackedCol<B>> {
        self.tracked_col_by_indices(&(0..self.num_total_tracked_cols()).collect::<Vec<usize>>())
    }

    /// Number of flat-view entries, the activator included and side
    /// segments excluded.
    pub fn num_total_tracked_cols(&self) -> usize {
        self.tracked_cols
            .values()
            .map(|c| c.segments_iter().count())
            .sum()
    }

    /// Number of flat-view entries that are not system columns.
    pub fn num_data_tracked_cols(&self) -> usize {
        self.tracked_polys()
            .keys()
            .filter(|field| !crate::is_system_column(field.name()))
            .count()
    }

    pub fn activator_tracked_poly(&self) -> Option<TrackedPoly<B>> {
        self.tracked_cols.iter().find_map(|(field, col)| {
            (field.name() == ACTIVATOR_COL_NAME).then(|| col.data_tracked_poly())
        })
    }

    /// The flat view as a text table, like DataFusion's `RecordBatch`
    /// formatter.
    pub fn pretty_string(&self) -> String {
        let flat = self.tracked_polys();
        if flat.is_empty() {
            return "TrackedTable<empty>".to_string();
        }

        let mut headers = Vec::with_capacity(flat.len() + 1);
        let mut columns: Vec<Vec<String>> = Vec::with_capacity(flat.len() + 1);

        for (field, poly) in flat.iter() {
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

/// Whether `aux` is a segment of the source column `primary`.
///
/// A name match decides it (`n_name__length` belongs to `n_name`) unless
/// several primaries share the name, which `ambiguous` lists. Then the two
/// fields must also agree on data type, nullability and metadata:
/// `TrackedTable::tracked_polys` builds each segment field from its primary
/// with exactly those three, so this is exact. Pairing duplicates by
/// position could attach one column's `__length` to the other's primary
/// and give a wrong proof without an error.
pub(crate) fn aux_belongs_to(
    aux: &FieldRef,
    primary: &FieldRef,
    ambiguous: &std::collections::HashSet<String>,
) -> bool {
    let Some(base) = crate::encoding::segment_base_name(aux.name()) else {
        return false;
    };
    if base != primary.name() {
        return false;
    }
    if !ambiguous.contains(base) {
        return true;
    }
    aux.data_type() == primary.data_type()
        && aux.is_nullable() == primary.is_nullable()
        && aux.metadata() == primary.metadata()
}

/// Group flat schema-order row-domain polynomials and side segments by
/// source column, in the order the primaries appear in `tracked_polys`.
/// Each aux or side segment goes to the source column
/// `segment_base_name` names. Row-domain aux share the table's activator;
/// side segments carry their own.
fn regroup_flat_into_tracked_cols<B: SnarkBackend>(
    tracked_polys: &IndexMap<FieldRef, TrackedPoly<B>>,
    side_cols: &IndexMap<FieldRef, PolyBundle<B>>,
) -> IndexMap<FieldRef, TrackedCol<B>> {
    let shared_activator = tracked_polys
        .iter()
        .find_map(|(field, poly)| (field.name() == ACTIVATOR_COL_NAME).then(|| poly.clone()));
    // An aux field whose primary is absent becomes its own `SingleSegment`
    // entry: a scratch table can hold `col__length` without `col`.
    let primary_present: std::collections::HashSet<String> = tracked_polys
        .keys()
        .filter(|f| crate::encoding::segment_base_name(f.name()).is_none())
        .map(|f| f.name().to_string())
        .collect();
    // Primary names that occur more than once: an un-aliased self-join
    // (TPC-H Q7 joins `nation` twice) puts two `n_name` primaries and two
    // `n_name__length` aux fields in one flat view. Matching by name alone
    // would give both lengths to the first `n_name`, so `aux_belongs_to`
    // compares the whole field for these names.
    let ambiguous_primaries: std::collections::HashSet<String> = {
        let mut seen = std::collections::HashSet::new();
        tracked_polys
            .keys()
            .filter(|f| crate::encoding::segment_base_name(f.name()).is_none())
            .filter(|f| !seen.insert(f.name().to_string()))
            .map(|f| f.name().to_string())
            .collect()
    };
    let mut out = IndexMap::with_capacity(tracked_polys.len());
    for (field, poly) in tracked_polys.iter() {
        if let Some(base) = crate::encoding::segment_base_name(field.name()) {
            if primary_present.contains(base) {
                // Attached when its primary is visited.
                continue;
            }
            out.insert(
                field.clone(),
                TrackedCol::new(poly.clone(), shared_activator.clone(), Some(field.clone())),
            );
            continue;
        }
        let primary_name = field.name();
        let mut row_aux_bundles: Vec<(String, PolyBundle<B>)> = Vec::new();
        let mut side_aux_bundles: Vec<(String, PolyBundle<B>)> = Vec::new();
        for (aux_field, aux_poly) in tracked_polys.iter() {
            if aux_field.name() == primary_name {
                continue;
            }
            if aux_belongs_to(aux_field, field, &ambiguous_primaries) {
                let suffix = &aux_field.name()[primary_name.len()..];
                row_aux_bundles.push((
                    suffix.to_string(),
                    PolyBundle::new(aux_poly.clone(), shared_activator.clone()),
                ));
            }
        }
        for (side_field, side) in side_cols.iter() {
            if aux_belongs_to(side_field, field, &ambiguous_primaries) {
                let suffix = &side_field.name()[primary_name.len()..];
                side_aux_bundles.push((suffix.to_string(), side.clone()));
            }
        }
        let col = if row_aux_bundles.is_empty() && side_aux_bundles.is_empty() {
            TrackedCol::new(poly.clone(), shared_activator.clone(), Some(field.clone()))
        } else {
            TrackedCol::new_multi_split(
                PolyBundle::new(poly.clone(), shared_activator.clone()),
                row_aux_bundles,
                side_aux_bundles,
                Some(field.clone()),
            )
        };
        out.insert(field.clone(), col);
    }
    out
}

/// A side-domain polynomial: one of the char-level polynomials of a string
/// column (paper §3.2: `__chars`, `__orig_ind`, `__int_ind`, `__bnd`). It
/// has its own `log_size`, and its activator is the contiguous-one
/// polynomial of weight `active_len`. The data stays in native form; the
/// commit and tracking passes build `MLE<F>` views from it.
#[derive(Clone, Debug, PartialEq)]
pub struct ArithSideCol {
    /// Zero-padded to `1 << log_size` entries.
    pub data: crate::encoding::SideColData,
    pub log_size: usize,
    /// Number of leading active entries.
    pub active_len: usize,
}

#[derive(Clone, Debug, PartialEq)]
/// An arithmetized table that is not tracked. It can be serialized.
pub struct ArithTable<F: PrimeField> {
    schema: Option<Schema>,
    polynomials: IndexMap<FieldRef, Arc<MLE<F>>>,
    log_size: usize,
    /// Keyed by the side segment's own field (`<col>__chars`). Committed
    /// separately from the row-domain `polynomials`.
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
    /// A table with no side-domain columns.
    pub fn new(
        schema: Option<Schema>,
        polynomials: IndexMap<FieldRef, Arc<MLE<F>>>,
        log_size: usize,
    ) -> Self {
        Self::new_with_side_cols(schema, polynomials, log_size, IndexMap::new())
    }

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

    pub fn side_cols(&self) -> &IndexMap<FieldRef, ArithSideCol> {
        &self.side_cols
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        schema: &Option<Schema>,
        polys: &IndexMap<FieldRef, Arc<MLE<F>>>,
        log_size: usize,
    ) -> SnarkResult<()> {
        polys.values().for_each(|poly| {
            assert_eq!(
                poly.num_vars(),
                log_size,
                "All columns must have the same log size as the table"
            );
        });

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

    /// The row-domain polynomials, one per flat field.
    pub fn polynomials(&self) -> &IndexMap<FieldRef, Arc<MLE<F>>> {
        &self.polynomials
    }

    /// The flat `polynomials` and `side_cols` grouped by source column
    /// name (`segment_base_name`), like `TrackedTable::tracked_cols`.
    pub fn arith_cols(&self) -> IndexMap<FieldRef, crate::arith_col::ArithCol<F>> {
        let mut out = IndexMap::with_capacity(self.polynomials.len());
        for (field, mle) in self.polynomials.iter() {
            if crate::encoding::segment_base_name(field.name()).is_some() {
                continue;
            }
            let primary_name = field.name();
            let mut aux_data: IndexMap<String, Arc<MLE<F>>> = IndexMap::new();
            for (aux_field, aux_mle) in self.polynomials.iter() {
                if aux_field.name() == primary_name {
                    continue;
                }
                if let Some(base) = crate::encoding::segment_base_name(aux_field.name())
                    && base == primary_name
                {
                    let suffix = &aux_field.name()[primary_name.len()..];
                    aux_data.insert(suffix.to_string(), aux_mle.clone());
                }
            }
            let mut side_data: IndexMap<String, ArithSideCol> = IndexMap::new();
            for (side_field, side) in self.side_cols.iter() {
                if let Some(base) = crate::encoding::segment_base_name(side_field.name())
                    && base == primary_name
                {
                    let suffix = &side_field.name()[primary_name.len()..];
                    side_data.insert(suffix.to_string(), side.clone());
                }
            }
            let col = if aux_data.is_empty() && side_data.is_empty() {
                crate::arith_col::ArithCol::new(mle.clone(), Some(field.clone()))
            } else {
                crate::arith_col::ArithCol::new_multi(
                    mle.clone(),
                    aux_data,
                    side_data,
                    Some(field.clone()),
                )
            };
            out.insert(field.clone(), col);
        }
        out
    }

    pub fn log_size(&self) -> usize {
        self.log_size
    }

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

    /// Number of row-domain columns, the activator included.
    pub fn num_total_cols(&self) -> usize {
        self.polynomials.len()
    }

    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    /// The evaluations of a `TrackedTable`'s row-domain columns. Side
    /// columns are dropped.
    pub fn from_tracked_table<B>(table: &TrackedTable<B>) -> ArithTable<B::F>
    where
        B: SnarkBackend,
    {
        let schema = table.schema();
        let size = table.size();
        let tracked_polys = table
            .tracked_polys()
            .into_iter()
            .map(|(field, poly)| {
                let evals = poly.evaluations();
                let mle = Arc::new(MLE::from_evaluations_slice(poly.log_size(), &evals));
                (field, mle)
            })
            .collect::<IndexMap<_, _>>();
        // TODO: recover the side columns. Their tracked polynomials must go
        // back to native values, whose element type follows from the suffix
        // (`__chars`, `__bnd` → Bytes; `__orig_ind`, `__int_ind` → U32).
        let side_cols: IndexMap<FieldRef, ArithSideCol> = IndexMap::new();
        let _ = table.side_cols(); // touch to keep it live if reactivated
        ArithTable::new_with_side_cols(schema, tracked_polys, size, side_cols)
    }

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

        // Side-domain columns follow: the count, then per column its field,
        // log_size, active_len, element-type tag and data. `active_len`
        // determines the activator, which is not stored.
        (self.side_cols.len() as u64).serialize_with_mode(&mut writer, compress)?;
        for (field_ref, side) in &self.side_cols {
            let field_bytes = serde_json::to_vec(field_ref.as_ref())
                .map_err(|_| SerializationError::InvalidData)?;
            field_bytes.serialize_with_mode(&mut writer, compress)?;
            (side.log_size as u64).serialize_with_mode(&mut writer, compress)?;
            (side.active_len as u64).serialize_with_mode(&mut writer, compress)?;
            // Element-type tag: 0 = Bytes, 1 = U32.
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

            let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
            let data = match tag {
                0 => {
                    let bytes = Vec::<u8>::deserialize_with_mode(&mut reader, compress, validate)?;
                    if bytes.len() != (1usize << log_size) {
                        return Err(SerializationError::InvalidData);
                    }
                    crate::encoding::SideColData::Bytes(bytes)
                }
                1 => {
                    let vals = Vec::<u32>::deserialize_with_mode(&mut reader, compress, validate)?;
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
