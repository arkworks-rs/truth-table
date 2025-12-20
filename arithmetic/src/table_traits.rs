use datafusion::arrow::datatypes::{FieldRef, Schema};
use indexmap::IndexMap;
use std::fmt::{Debug, Display};

pub trait IsTable: Default + Clone + Display + Debug + 'static {
    type Scalar: Clone;
    type Column: Clone;

    fn columns(&self) -> IndexMap<FieldRef, Self::Column>;
    fn columns_iter(&self) -> Box<dyn Iterator<Item = (&FieldRef, &Self::Column)> + '_>;
    fn schema(&self) -> Option<Schema>;
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
    fn rename_column(&mut self, idx: usize, new_name: &str);
    fn mul_columns(left: &Self::Column, right: &Self::Column) -> Self::Column;
    fn mul_column_scalar(col: &Self::Column, scalar: Self::Scalar) -> Self::Column;
    fn add_column_scalar(col: &Self::Column, scalar: Self::Scalar) -> Self::Column;
    fn scalar_one() -> Self::Scalar;
    fn scalar_neg_one() -> Self::Scalar;
    fn column_from_scalar(
        scalar: Self::Scalar,
        log_size: usize,
        activator: &Self::Column,
    ) -> Option<Self::Column>;
}
