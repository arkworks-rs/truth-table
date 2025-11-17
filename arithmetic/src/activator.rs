use std::sync::Arc;

use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef},
    common::Column,
};
use datafusion_expr::Expr;
use once_cell::sync::Lazy;

pub const ACTIVATOR_COL_NAME: &str = "__activator__";
pub static ACTIVATOR_FIELD: Lazy<FieldRef> =
    Lazy::new(|| Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false)));
pub static ACTIVATOR_EXPR: Lazy<Expr> =
    Lazy::new(|| Expr::Column(Column::from_name(ACTIVATOR_COL_NAME)));
