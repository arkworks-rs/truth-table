//! Arithmetization of database objects (tables, columns, Arrow data types):
//! their encoding as the polynomials the proof system works on.

pub mod arith_col;
pub mod col;
pub mod col_oracle;
pub mod encoding;
pub mod errors;
pub mod fingerprint;
pub mod table;
pub mod table_oracle;

pub use col::{
    ACTIVATOR_COL_NAME, ACTIVATOR_EXPR, ACTIVATOR_FIELD, ROW_ID_COL_NAME, ROW_ID_EXPR,
    ROW_ID_FIELD, is_system_column,
};
