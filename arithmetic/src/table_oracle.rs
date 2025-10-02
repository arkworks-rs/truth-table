// Imports
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    verifier::{errors::VerifierError, structs::oracle::TrackedOracle, Verifier},
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use crate::{col_oracle::ArithColOracle, table::ArithTable};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use derivative::Derivative;
use serde_json::{from_slice as schema_from_slice, to_vec as schema_to_vec};
use std::{collections::HashMap, convert::TryFrom, sync::Arc};

////////////////////////////////////////////////////////////////////////////////////////////////////////
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    PartialEq(bound = "UvPCS: PCS<F>")
)]
/// The abstraction of an arithmetic table in a PIOP verifier. It contains the
/// following:
/// - An optional schema of the table
/// - A vector of column oracles (one for each column)
/// - An optional activator oracle, If none, all the rows are active
/// - The log size of the table
pub struct ArithTableOracle<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    schema: Option<Schema>,
    data_oracles: HashMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>>,
    log_size: usize,
}

// Custom Debug impl to avoid requiring `MvPCS`/`UvPCS` to be Debug.
impl<F, MvPCS, UvPCS> core::fmt::Debug for ArithTableOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArithTable")
            .field("num_cols", &self.num_cols())
            .field("log_size", &self.log_size())
            .finish()
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> ArithTableOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Creates a new arithmetized table given an optional schema, a vector of
    /// column oracles and the log size of the table
    pub fn new(
        schema: Option<Schema>,
        data_oracles: HashMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>>,
        log_size: usize,
    ) -> Self {
        Self {
            schema,
            data_oracles,
            log_size,
        }
    }
    /// Returns the log size of the table
    pub fn log_size(&self) -> usize {
        self.log_size
    }

    /// Given a list of column indices and a list of challenges, returns the
    /// folded column oracle, which is the linear combination of the specified
    /// columns with the specified challenges as coefficients
    pub fn fold(&self, col_inds: &[usize], challs: &[F]) -> ArithColOracle<F, MvPCS, UvPCS> {
        let schema = self
            .schema
            .as_ref()
            .expect("schema required for indexed folding");
        let first_field = schema.field(col_inds[0]).clone();
        let mut folded: TrackedOracle<F, MvPCS, UvPCS> = &self
            .data_oracles
            .get(&first_field)
            .expect("column oracle not found")
            .clone()
            * challs[0];
        for i in 1..col_inds.len() {
            let field_ref = schema.field(col_inds[i]).clone();
            let col_oracle = self
                .data_oracles
                .get(&field_ref)
                .expect("column oracle not found")
                .clone();
            folded += &(&col_oracle * challs[i]);
        }
        ArithColOracle::new(None, folded, self.actvtr_poly(), self.log_size)
    }

    /// Returns the folded column oracle of all the columns in the table with
    /// the specified challenges as coefficients
    pub fn fold_all(&self, challs: &[F]) -> ArithColOracle<F, MvPCS, UvPCS> {
        let schema = self
            .schema
            .as_ref()
            .expect("schema required for indexed folding");
        let cols: Vec<usize> = (0..schema.fields().len()).collect();
        self.fold(&cols, challs)
    }

    /// Returns the column at the specified index
    /// Note that the output of the function is not just an oracle, but an
    /// `ArithColOracle` wrapper, which also contains the activator oracle (if
    /// any)
    pub fn col(&self, col_ind: usize) -> ArithColOracle<F, MvPCS, UvPCS> {
        let schema = self
            .schema
            .as_ref()
            .expect("schema required for column access");
        let field_ref = schema.field(col_ind).clone();
        let data_type = schema.field(col_ind).data_type().clone();
        let oracle = self
            .data_oracles
            .get(&field_ref)
            .expect("column oracle not found")
            .clone();
        ArithColOracle::new(Some(data_type), oracle, self.actvtr_poly(), self.log_size)
    }

    /// Returns the column oracles at the specified indices
    /// Note that the outputs of the function are not just  oracles, but
    /// `ArithColOracle` wrappers, which also contain the activator oracles (if
    /// any)
    pub fn cols(&self, indice: &[usize]) -> Vec<ArithColOracle<F, MvPCS, UvPCS>> {
        indice.iter().map(|&i| self.col(i)).collect()
    }
    /// Returns all the column oracles in the table
    /// Note that the outputs of the function are not just  oracles, but
    /// `ArithColOracle` wrappers, which also contain the activator oracles (if
    /// any)
    pub fn all_cols(&self) -> Vec<ArithColOracle<F, MvPCS, UvPCS>> {
        self.cols(&(0..self.num_cols()).collect::<Vec<usize>>())
    }

    /// Returns the number of columns in the table
    pub fn num_cols(&self) -> usize {
        self.data_oracles.len()
    }
    /// Constructs an `ArithTableOracle` from an `ArithTable` by tracking the
    /// column and activator polynomials using the provided verifier
    /// It's assumed that the verifier already has the commitments of the
    /// polynomials being tracked
    pub fn from(
        table: ArithTable<F, MvPCS, UvPCS>,
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) -> SnarkResult<Self> {
        let schema = table.schema().clone();
        let log_size = table.log_size();

        let mut data_map = HashMap::with_capacity(table.num_cols());
        for (field_ref, poly) in table.columns() {
            let id = poly.id_or_const().left().ok_or_else(|| {
                VerifierError::VerifierCheckFailed(
                    "Table column polynomial is constant; expected commitment id".into(),
                )
            })?;
            let oracle = verifier.track_mv_com_by_id(id)?;
            data_map.insert(field_ref.clone(), oracle);
        }

        Ok(Self::new(schema, data_map, log_size))
    }

    /// Returns the vector of raw column oracles in the table
    pub fn data_oracles(&self) -> HashMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>> {
        self.data_oracles.clone()
    }
    /// Returns the optional schema of the table
    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }
    /// Returns the optional activator oracle of the table
    pub fn actvtr_poly(&self) -> Option<TrackedOracle<F, MvPCS, UvPCS>> {
        self.data_oracles
            .iter()
            .find_map(|(field, oracle)| (field.name() == "activator").then(|| oracle.clone()))
    }
}

/// The abstraction of an arithmetic table in a PIOP verifier. It contains the
/// following:
/// - An optional schema of the table
/// - A vector of column oracles (one for each column)
/// - An optional activator oracle, If none, all the rows are active
/// - The log size of the table
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    PartialEq(bound = "UvPCS: PCS<F>")
)]
pub struct SerializableArithTableOracle<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    _phantom: std::marker::PhantomData<UvPCS>,
    schema: Option<Schema>,
    data_oraclemitments: HashMap<FieldRef, MvPCS::Commitment>,
    log_size: usize,
}

impl<F, MvPCS, UvPCS> SerializableArithTableOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn from_arith_table_oracle(table_oracle: &ArithTableOracle<F, MvPCS, UvPCS>) -> Self
    where
        MvPCS::Commitment: Clone,
    {
        let data_oraclemitments = table_oracle
            .data_oracles()
            .iter()
            .map(|(field_ref, oracle)| (field_ref.clone(), oracle.commitment()))
            .collect();
        Self {
            _phantom: std::marker::PhantomData,
            schema: table_oracle.schema(),
            data_oraclemitments,
            log_size: table_oracle.log_size(),
        }
    }

    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    pub fn data_oraclemitments(&self) -> &HashMap<FieldRef, MvPCS::Commitment> {
        &self.data_oraclemitments
    }

    pub fn activator_commitment(&self) -> Option<&MvPCS::Commitment> {
        self.data_oraclemitments
            .iter()
            .find_map(|(field, comm)| (field.name() == "activator").then(|| comm))
    }
}

impl<F, MvPCS, UvPCS> CanonicalSerialize for SerializableArithTableOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>> + Sync,
    MvPCS::Commitment: CanonicalSerialize + Valid,
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
            let mut keys = self.data_oraclemitments.keys().cloned().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.name().cmp(b.name()));
            keys
        };

        let count = ordered_fields.len() as u64;
        count.serialize_with_mode(&mut writer, compress)?;

        for field_ref in ordered_fields.iter() {
            let commitment = self
                .data_oraclemitments
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
            let mut keys = self.data_oraclemitments.keys().cloned().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.name().cmp(b.name()));
            keys
        };

        size += (ordered_fields.len() as u64).serialized_size(compress);
        for field_ref in ordered_fields.iter() {
            let commitment = self
                .data_oraclemitments
                .get(field_ref)
                .expect("commitment missing for field");
            size += commitment.serialized_size(compress);
        }

        size + (self.log_size as u64).serialized_size(compress)
    }
}

impl<F, MvPCS, UvPCS> CanonicalDeserialize for SerializableArithTableOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>> + Sync,
    MvPCS::Commitment: CanonicalDeserialize + Valid,
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
        let mut data_oraclemitments = HashMap::with_capacity(count_usize);

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
            let commitment =
                MvPCS::Commitment::deserialize_with_mode(&mut reader, compress, validate)?;
            data_oraclemitments.insert(field_ref, commitment);
        }

        let log_size_raw = u64::deserialize_with_mode(&mut reader, compress, validate)?;
        let log_size =
            usize::try_from(log_size_raw).map_err(|_| SerializationError::InvalidData)?;

        Ok(Self {
            _phantom: std::marker::PhantomData,
            schema,
            data_oraclemitments,
            log_size,
        })
    }
}

impl<F, MvPCS, UvPCS> Valid for SerializableArithTableOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>> + Sync,
    MvPCS::Commitment: Valid,
{
    fn check(&self) -> Result<(), SerializationError> {
        for commitment in self.data_oraclemitments.values() {
            commitment.check()?;
        }
        Ok(())
    }
}
