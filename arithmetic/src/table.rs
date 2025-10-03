use std::sync::Arc;

use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::{structs::polynomial::TrackedPoly, Prover},
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use datafusion::arrow::{
    array::RecordBatch,
    datatypes::{Field, FieldRef, Schema},
};
use derivative::Derivative;
use serde_json::{from_slice as schema_from_slice, to_vec as schema_to_vec};

use crate::{
    col::TrackedCol, ctx::ProverCtx, encoding::encode_arrow_array_to_field, errors::EncodeError,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
/// An abstraction of an arithmetized table in dbSNARK
/// An arithmetized table is represented by a set of polynomials representing
/// the data columns and a single activator polynomial If the activator
/// polynomial is None, all the rows are active
pub struct TrackedTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The schema of the table; i.e. the metadata about the table
    schema: Option<Schema>,
    /// The polynomials representing the data columns, stored in schema order
    data_polys: Vec<(FieldRef, TrackedPoly<F, MvPCS, UvPCS>)>,
    size: usize,
}

// Custom Debug impl to avoid requiring `MvPCS`/`UvPCS` to be Debug.
impl<F, MvPCS, UvPCS> core::fmt::Debug for TrackedTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrackedTable")
            .field("num_cols", &self.num_cols())
            .field("log_size", &self.log_size())
            .field("size", &self.size)
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
        let data_polys = self
            .data_polys
            .iter()
            .map(|(field, poly)| (field.clone(), poly.deep_clone(prover.clone())))
            .collect();
        Self::new(self.schema.clone(), data_polys, self.size)
    }
}

impl<F, MvPCS, UvPCS> TrackedTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        schema: Option<Schema>,
        data_polys: Vec<(FieldRef, TrackedPoly<F, MvPCS, UvPCS>)>,
        // TODO: See if we can remove this
        size: usize,
    ) -> Self {
        Self {
            schema,
            data_polys,
            size,
        }
    }
    pub fn log_size(&self) -> usize {
        self.data_polys
            .first()
            .expect("table should have columns")
            .1
            .log_size()
    }

    pub fn prover(&self) -> Prover<F, MvPCS, UvPCS> {
        Prover::new_from_tracker_rc(
            self.data_polys
                .first()
                .expect("table should have columns")
                .1
                .tracker(),
        )
    }

    pub fn fold(&self, col_inds: &[usize], challs: &[F]) -> TrackedCol<F, MvPCS, UvPCS> {
        assert_eq!(col_inds.len(), challs.len());
        let mut folded: TrackedPoly<F, MvPCS, UvPCS> =
            &self.data_polys[col_inds[0]].1.clone() * challs[0];
        for i in 1..col_inds.len() {
            folded += &(&self.data_polys[col_inds[i]].1 * challs[i]);
        }
        TrackedCol::new(None, folded, self.actvtr_poly())
    }

    pub fn fold_all(&self, challs: &[F]) -> TrackedCol<F, MvPCS, UvPCS> {
        self.fold(&(0..self.num_cols()).collect::<Vec<usize>>(), challs)
    }

    pub fn col(&self, col_ind: usize) -> TrackedCol<F, MvPCS, UvPCS> {
        TrackedCol::new(
            self.schema.as_ref().map(|schema| {
                if col_ind >= schema.fields().len() {
                    panic!(
                        "Column index {} out of bounds (schema: {:?})",
                        col_ind, schema
                    );
                }
                schema.field(col_ind).clone().data_type().clone()
            }),
            self.data_polys[col_ind].1.clone(),
            self.actvtr_poly(),
        )
    }

    pub fn col_by_name(&self, name: &str) -> Option<TrackedCol<F, MvPCS, UvPCS>> {
        let idx = self
            .schema
            .as_ref()
            .and_then(|schema| schema.index_of(name).ok())?;
        Some(self.col(idx))
    }

    pub fn data_polys(&self) -> Vec<TrackedPoly<F, MvPCS, UvPCS>> {
        self.data_polys
            .iter()
            .map(|(_, poly)| poly.clone())
            .collect()
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn cols(&self, indice: &[usize]) -> Vec<TrackedCol<F, MvPCS, UvPCS>> {
        indice.iter().map(|&i| self.col(i)).collect()
    }

    pub fn all_cols(&self) -> Vec<TrackedCol<F, MvPCS, UvPCS>> {
        self.cols(&(0..self.num_cols()).collect::<Vec<usize>>())
    }

    pub fn num_cols(&self) -> usize {
        self.data_polys.len()
    }

    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    pub fn actvtr_poly(&self) -> Option<TrackedPoly<F, MvPCS, UvPCS>> {
        self.data_polys
            .iter()
            .find_map(|(field, poly)| (field.name() == "activator").then(|| poly.clone()))
    }

    pub fn columns(&self) -> impl Iterator<Item = (&FieldRef, &TrackedPoly<F, MvPCS, UvPCS>)> {
        self.data_polys.iter().map(|(field, poly)| (field, poly))
    }
}

#[derive(Clone, Debug, PartialEq)]
/// A serializable representation of an [`TrackedTable`], where the tracked
/// polynomials are materialized so the table can be persisted or transmitted
/// without the original prover tracker state.
pub struct ArithTable<F: PrimeField> {
    schema: Option<Schema>,
    data_polys: Vec<(FieldRef, MLE<F>)>,
    size: usize,
}

impl<F: PrimeField> ArithTable<F> {
    pub fn new(schema: Option<Schema>, data_polys: Vec<(FieldRef, MLE<F>)>, size: usize) -> Self {
        Self {
            schema,
            data_polys,
            size,
        }
    }

    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    pub fn data_polys(&self) -> &[(FieldRef, MLE<F>)] {
        &self.data_polys
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn num_cols(&self) -> usize {
        self.data_polys.len()
    }

    pub fn from_tracked_Table<MvPCS, UvPCS>(table: &TrackedTable<F, MvPCS, UvPCS>) -> Self
    where
        MvPCS: PCS<F, Poly = MLE<F>>,
        UvPCS: PCS<F, Poly = LDE<F>>,
    {
        let schema = table.schema();
        let size = table.size();
        let data_polys = table
            .columns()
            .map(|(field, poly)| {
                let evals = poly.evaluations();
                let mle = MLE::from_evaluations_slice(poly.log_size(), &evals);
                (field.clone(), mle)
            })
            .collect();
        Self::new(schema, data_polys, size)
    }
}

impl<F: PrimeField, MvPCS, UvPCS> From<TrackedTable<F, MvPCS, UvPCS>> for ArithTable<F>
where
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn from(table: TrackedTable<F, MvPCS, UvPCS>) -> Self {
        Self::from_tracked_Table(&table)
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

        (self.data_polys.len() as u64).serialize_with_mode(&mut writer, compress)?;

        for (field_ref, mle) in &self.data_polys {
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

        (self.size as u64).serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut size = self.schema.is_some().serialized_size(compress);

        if let Some(schema) = &self.schema {
            let schema_bytes = schema_to_vec(schema).expect("schema serialization should succeed");
            size += schema_bytes.serialized_size(compress);
        }

        size += (self.data_polys.len() as u64).serialized_size(compress);
        for (field_ref, mle) in &self.data_polys {
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

        size + (self.size as u64).serialized_size(compress)
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

        let mut data_polys = Vec::with_capacity(column_count);
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
            let mle = MLE::from_evaluations_vec(nv, evaluations);
            data_polys.push((field_ref, mle));
        }

        let size_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let size = usize::try_from(size_raw).map_err(|_| SerializationError::InvalidData)?;

        let table = Self::new(schema, data_polys, size);
        table.check()?;
        Ok(table)
    }
}

impl<F: PrimeField> Valid for ArithTable<F> {
    fn check(&self) -> Result<(), SerializationError> {
        if let Some(schema) = &self.schema {
            if schema.fields().len() != self.data_polys.len() {
                return Err(SerializationError::InvalidData);
            }
        }

        for (_, mle) in &self.data_polys {
            if self.size != 0 && (1usize << mle.num_vars()) != self.size {
                return Err(SerializationError::InvalidData);
            }
        }
        Ok(())
    }
}
