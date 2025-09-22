//! This crate provides a set of tools for arithmetizing (encoding) and
//! de-arithmetizing (decoding) data-structures related to databases; i.e.
//! tables, columns, data tpypes, etc.
//! Arithmetization is the process of converting a data structure into algebraic
//! objects used in proof-systems , like polynomials.

///////// Modules /////////
pub mod col;
pub mod errors;
pub mod table;
///////// Imports /////////
#[macro_export]
macro_rules! downcast_and_encode {
    ($ARRAY:expr, $OUTPUT_VEC:expr, $F:ty) => {
        use $crate::col::ColAdapter;
        match $ARRAY.data_type() {
            datafusion::arrow::datatypes::DataType::Int32 => {
                let typed_array = $ARRAY
                    .as_any()
                    .downcast_ref::<datafusion::arrow::array::Int32Array>()
                    .unwrap();
                $OUTPUT_VEC.append(&mut typed_array.encode()?);
            },
            datafusion::arrow::datatypes::DataType::Int64 => {
                let typed_array = $ARRAY
                    .as_any()
                    .downcast_ref::<datafusion::arrow::array::Int64Array>()
                    .unwrap();
                $OUTPUT_VEC.append(&mut typed_array.encode()?);
            },
            _ => {
                panic!(
                    "Unsupported data type for conversion: {:?}",
                    $ARRAY.data_type()
                );
            },
        }
    };
}
