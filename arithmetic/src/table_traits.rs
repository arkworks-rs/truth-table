use datafusion::arrow::datatypes::{FieldRef, Schema};
use indexmap::IndexMap;
use std::fmt::{Debug, Display};

pub trait IsTable: Default + Clone + Display + Debug + 'static {
    type Scalar: Clone;
    type Column: Clone;

    fn columns(&self) -> IndexMap<FieldRef, Self::Column>;
    fn columns_iter(&self) -> Box<dyn Iterator<Item = (&FieldRef, &Self::Column)> + '_>;
    fn schema_ref(&self) -> Option<&Schema>;
    fn log_size(&self) -> usize;
    fn new_with(
        schema: Option<Schema>,
        columns: IndexMap<FieldRef, Self::Column>,
        log_size: usize,
    ) -> Self;
    fn subtable_by_indices(&self, indices: &[usize]) -> Self;
    fn data_columns_indices(&self) -> Vec<usize>;
    fn activator_column(&self) -> Option<Self::Column>;
    fn column_from_scalar(
        scalar: Self::Scalar,
        log_size: usize,
        activator: &Self::Column,
    ) -> Option<Self::Column>;
}
