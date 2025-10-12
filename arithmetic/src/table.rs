use std::sync::Arc;

use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::DeepClone,
    prover::{structs::polynomial::TrackedPoly, Prover},
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use derivative::Derivative;
use indexmap::IndexMap;
use serde_json::{from_slice as schema_from_slice, to_vec as schema_to_vec};

use crate::{col::TrackedCol, ACTIVATOR_COL_NAME};

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
/// An abstraction of a tracked arithmetized table in dbSNARK
/// A tracked arithmetized table is represented by a set of tracked polynomials
/// representing the columns
pub struct TrackedTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The schema of the table, if any
    schema: Option<Schema>,
    /// The polynomials representing the columns, stored in schema order
    tracked_polys: IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>>,
    /// The log size of the table
    log_size: usize,
}

impl<F, MvPCS, UvPCS> core::fmt::Debug for TrackedTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedTable")
            .field("num_total_cols", &self.num_total_tracked_cols())
            .field("num_data_cols", &self.num_data_tracked_cols())
            .field("log_size", &self.log_size())
            .finish()
    }
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for TrackedTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        let tracked_polys = self
            .tracked_polys
            .iter()
            .map(|(field, poly)| (field.clone(), poly.deep_clone(prover.clone())))
            .collect::<IndexMap<_, _>>();
        Self::new(self.schema.clone(), tracked_polys, self.log_size)
    }
}

impl<F, MvPCS, UvPCS> TrackedTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Constructs a new `TrackedTable` from the provided schema (if any),
    /// tracked polynomials, and log size of the table
    pub fn new(
        schema: Option<Schema>,
        tracked_polys: IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>>,
        log_size: usize,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&schema, &tracked_polys, log_size).unwrap();
        }

        Self {
            schema,
            tracked_polys,
            log_size,
        }
    }

    #[cfg(debug_assertions)]
    fn check_new_args(
        schema: &Option<Schema>,
        tracked_polys: &IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>>,
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
    pub fn tracked_polys(&self) -> IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>> {
        self.tracked_polys.clone()
    }

    /// Returns the optional schema of the table
    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
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
    pub fn fold(&self, col_inds: &[usize], challs: &[F]) -> TrackedCol<F, MvPCS, UvPCS> {
        debug_assert_eq!(col_inds.len(), challs.len());
        let first_idx = *col_inds
            .first()
            .expect("fold requires at least one column index");
        let first_chall = challs
            .first()
            .copied()
            .expect("fold requires at least one challenge");
        let (_, first_poly) = self
            .tracked_polys
            .get_index(first_idx)
            .expect("column index out of bounds");
        let mut folded: TrackedPoly<F, MvPCS, UvPCS> = first_poly * first_chall;
        for (&col_idx, &chall) in col_inds.iter().zip(challs).skip(1) {
            let (_, poly) = self
                .tracked_polys
                .get_index(col_idx)
                .expect("column index out of bounds");
            let term = poly * chall;
            folded += &term;
        }
        TrackedCol::new(folded, self.activator_tracked_poly(), None)
    }
    /// Folds all the data (i.e. excluding the activator column) tracked column
    /// polynomials
    pub fn fold_all_data_columns(&self, challs: &[F]) -> TrackedCol<F, MvPCS, UvPCS> {
        self.fold(
            &(0..self.num_data_tracked_cols()).collect::<Vec<usize>>(),
            challs,
        )
    }

    /// Returns the tracked column at the specified index
    pub fn tracked_col_by_ind(&self, ind: usize) -> TrackedCol<F, MvPCS, UvPCS> {
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
    pub fn tracked_col_by_name(&self, name: &str) -> Option<TrackedCol<F, MvPCS, UvPCS>> {
        let idx = self
            .schema
            .as_ref()
            .and_then(|schema| schema.index_of(name).ok())?;
        Some(self.tracked_col_by_ind(idx))
    }

    /// Returns the tracked columns at the specified indices
    pub fn tracked_col_by_indices(&self, indices: &[usize]) -> Vec<TrackedCol<F, MvPCS, UvPCS>> {
        indices
            .iter()
            .map(|&i| self.tracked_col_by_ind(i))
            .collect()
    }

    /// Returns all the tracked column polynomials in the table, including the
    /// activator column (if any)
    pub fn all_tracked_cols(&self) -> Vec<TrackedCol<F, MvPCS, UvPCS>> {
        self.tracked_col_by_indices(&(0..self.num_total_tracked_cols()).collect::<Vec<usize>>())
    }

    // Number of data columns including  activator (if any)
    pub fn num_total_tracked_cols(&self) -> usize {
        self.tracked_polys.len()
    }

    // Number of data columns excluding possibly activator (if any)
    pub fn num_data_tracked_cols(&self) -> usize {
        self.tracked_polys.len() - (self.activator_tracked_poly().is_some() as usize)
    }

    /// Returns the tracked polynomial of the activator column, if any
    pub fn activator_tracked_poly(&self) -> Option<TrackedPoly<F, MvPCS, UvPCS>> {
        self.tracked_polys
            .iter()
            .find_map(|(field, poly)| (field.name() == ACTIVATOR_COL_NAME).then(|| poly.clone()))
    }
}

#[derive(Clone, Debug, PartialEq)]
/// An abstraction of an arithmetized table in dbSNARK
/// An arithmetic table might not be tracked and can be serialized and
/// deserialized
pub struct ArithTable<F: PrimeField> {
    schema: Option<Schema>,
    polynomials: IndexMap<FieldRef, Arc<MLE<F>>>,
    log_size: usize,
}

impl<F: PrimeField> ArithTable<F> {
    /// Constructs a new `ArithTable`
    pub fn new(
        schema: Option<Schema>,
        polynomials: IndexMap<FieldRef, Arc<MLE<F>>>,
        log_size: usize,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            Self::check_new_args(&schema, &polynomials, log_size).unwrap();
        }

        Self {
            schema,
            polynomials,
            log_size,
        }
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

    /// Number of columns in the table including activator (if any)
    pub fn num_total_cols(&self) -> usize {
        self.polynomials.len()
    }

    /// Returns the optional schema of the table
    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    /// Constructs an `ArithTable` from a `TrackedTable` by extracting
    pub fn from_tracked_table<MvPCS, UvPCS>(table: &TrackedTable<F, MvPCS, UvPCS>) -> Self
    where
        MvPCS: PCS<F, Poly = MLE<F>>,
        UvPCS: PCS<F, Poly = LDE<F>>,
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
            .collect();
        Self::new(schema, tracked_polys, size)
    }

    /// Returns the polynomial of the activator polynomial, if any
    pub fn activator_polynomial(&self) -> Option<&Arc<MLE<F>>> {
        self.polynomials
            .iter()
            .find_map(|(field, poly)| (field.name() == ACTIVATOR_COL_NAME).then_some(poly))
    }
}

impl<F: PrimeField, MvPCS, UvPCS> From<TrackedTable<F, MvPCS, UvPCS>> for ArithTable<F>
where
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn from(table: TrackedTable<F, MvPCS, UvPCS>) -> Self {
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

        size + (self.size() as u64).serialized_size(compress)
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

        let table = Self::new(schema, polynomials, size);
        table.check()?;
        Ok(table)
    }
}

impl<F: PrimeField> Valid for ArithTable<F> {
    fn check(&self) -> Result<(), SerializationError> {
        if let Some(schema) = &self.schema {
            if schema.fields().len() != self.polynomials.len() {
                return Err(SerializationError::InvalidData);
            }
        }

        for (_, mle) in &self.polynomials {
            if self.size() != 0 && (1usize << mle.num_vars()) != self.size() {
                return Err(SerializationError::InvalidData);
            }
        }
        Ok(())
    }
}
