use std::{fmt::Display, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, is_system_column};
use datafusion::arrow::datatypes::{FieldRef, Schema, SchemaRef};
use indexmap::IndexMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaterializationKind {
    Materialized,
    Virtual,
}

impl MaterializationKind {
    pub fn from_bool(materialized: bool) -> Self {
        if materialized {
            Self::Materialized
        } else {
            Self::Virtual
        }
    }

    pub fn as_bool(&self) -> bool {
        matches!(self, Self::Materialized)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColHint {
    pub materialization: MaterializationKind,
    pub degree_bound: Option<usize>,
}

impl ColHint {
    pub fn materialized() -> Self {
        Self {
            materialization: MaterializationKind::Materialized,
            degree_bound: None,
        }
    }

    pub fn virtualized() -> Self {
        Self {
            materialization: MaterializationKind::Virtual,
            degree_bound: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardinalityHint {
    Unknown,
    PowerOfTwoDomain(usize),
}

#[derive(Clone, Debug)]
pub struct VerifierHint {
    schema: SchemaRef,
    columns: IndexMap<FieldRef, ColHint>,
    log_size: usize,
    cardinality: CardinalityHint,
    has_activator: bool,
    has_row_id: bool,
}

impl VerifierHint {
    pub fn new(
        schema: SchemaRef,
        columns: IndexMap<FieldRef, ColHint>,
        log_size: usize,
        cardinality: CardinalityHint,
    ) -> Self {
        let has_activator = schema
            .fields()
            .iter()
            .any(|field| field.name() == ACTIVATOR_COL_NAME);
        let has_row_id = schema
            .fields()
            .iter()
            .any(|field| field.name() == ROW_ID_COL_NAME);

        Self {
            schema,
            columns,
            log_size,
            cardinality,
            has_activator,
            has_row_id,
        }
    }

    pub fn new_virtual(schema: SchemaRef, log_size: usize) -> Self {
        let columns = schema
            .fields()
            .iter()
            .map(|field| (field.clone(), ColHint::virtualized()))
            .collect::<IndexMap<_, _>>();
        Self::new(
            schema,
            columns,
            log_size,
            CardinalityHint::PowerOfTwoDomain(1usize << log_size),
        )
    }

    pub fn new_materialized(schema: SchemaRef, log_size: usize) -> Self {
        let columns = schema
            .fields()
            .iter()
            .map(|field| (field.clone(), ColHint::materialized()))
            .collect::<IndexMap<_, _>>();
        Self::new(
            schema,
            columns,
            log_size,
            CardinalityHint::PowerOfTwoDomain(1usize << log_size),
        )
    }

    pub fn from_field_materialization(
        schema: SchemaRef,
        field_materialization: IndexMap<FieldRef, bool>,
        log_size: usize,
    ) -> Self {
        let columns = field_materialization
            .into_iter()
            .map(|(field, mat)| {
                (
                    field,
                    ColHint {
                        materialization: MaterializationKind::from_bool(mat),
                        degree_bound: None,
                    },
                )
            })
            .collect::<IndexMap<_, _>>();

        Self::new(
            schema,
            columns,
            log_size,
            CardinalityHint::PowerOfTwoDomain(1usize << log_size),
        )
    }

    pub fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    pub fn schema_owned(&self) -> SchemaRef {
        self.schema.clone()
    }

    pub fn columns(&self) -> &IndexMap<FieldRef, ColHint> {
        &self.columns
    }

    pub fn col_hint(&self, field: &FieldRef) -> Option<&ColHint> {
        self.columns.get(field)
    }

    pub fn materialization_iter(&self) -> impl Iterator<Item = (&FieldRef, &ColHint)> {
        self.columns.iter()
    }

    pub fn is_materialized(&self, field: &FieldRef) -> Option<bool> {
        self.columns.get(field).map(|hint| hint.materialization.as_bool())
    }

    pub fn log_size(&self) -> usize {
        self.log_size
    }

    pub fn cardinality(&self) -> &CardinalityHint {
        &self.cardinality
    }

    pub fn has_activator(&self) -> bool {
        self.has_activator
    }

    pub fn has_row_id(&self) -> bool {
        self.has_row_id
    }

    pub fn set_cardinality(&mut self, cardinality: CardinalityHint) {
        self.cardinality = cardinality;
    }

    pub fn data_column_names(&self) -> Vec<String> {
        self.schema
            .fields()
            .iter()
            .filter(|field| !is_system_column(field.name()))
            .map(|field| field.name().to_string())
            .collect()
    }

    pub fn with_schema(self, schema: SchemaRef) -> Self {
        let mut next = self;
        next.schema = schema.clone();
        next.has_activator = schema
            .fields()
            .iter()
            .any(|field| field.name() == ACTIVATOR_COL_NAME);
        next.has_row_id = schema
            .fields()
            .iter()
            .any(|field| field.name() == ROW_ID_COL_NAME);
        next
    }

    pub fn empty_with_log_size(log_size: usize) -> Self {
        Self::new(
            Arc::new(Schema::empty()),
            IndexMap::new(),
            log_size,
            CardinalityHint::PowerOfTwoDomain(1usize << log_size),
        )
    }
}

impl Display for VerifierHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (materialized, virtualized): (Vec<_>, Vec<_>) = self
            .columns
            .iter()
            .partition(|(_, hint)| matches!(hint.materialization, MaterializationKind::Materialized));

        let materialized_cols = materialized
            .into_iter()
            .map(|(field, _)| field.name().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let virtual_cols = virtualized
            .into_iter()
            .map(|(field, _)| field.name().to_string())
            .collect::<Vec<_>>()
            .join(",");

        writeln!(f, "VerifierHint with {} columns", self.columns.len())?;
        writeln!(f, "log_size={}", self.log_size)?;
        writeln!(f, "cardinality={:?}", self.cardinality)?;
        writeln!(f, "Materialized: ({materialized_cols})")?;
        write!(f, "Virtual: ({virtual_cols})")
    }
}
