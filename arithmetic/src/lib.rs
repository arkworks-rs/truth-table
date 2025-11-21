//! This crate provides a set of tools for arithmetizing (encoding) and
//! de-arithmetizing (decoding) data-structures related to databases; i.e.
//! tables, columns, data tpypes, etc.
//! Arithmetization is the process of converting a data structure into algebraic
//! objects used in proof-systems , like polynomials.

///////// Modules /////////
pub mod activator;
pub mod col;
pub mod col_oracle;
pub mod ctx;
pub mod encoding;
pub mod errors;
pub mod table;
pub mod table_oracle;

pub use activator::{ACTIVATOR_COL_NAME, ACTIVATOR_EXPR, ACTIVATOR_FIELD};
