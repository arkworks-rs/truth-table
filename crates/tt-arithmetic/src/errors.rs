use datafusion::arrow::datatypes::DataType;
use thiserror::Error;
/// A `enum` specifying the possible failure modes of the PCS.
#[derive(Error, Debug)]
pub enum FieldAdapterError {
    #[error("Encode Error")]
    TranscriptError(#[from] EncodeError),
    #[error("Decode Error")]
    ArithErrors(#[from] DecodeError),
}

#[derive(Error, Debug)]
pub enum EncodeError {
    #[error("Value of type `{0}` cannot be converted to a PrimeField element.")]
    TypeNotSupported(String),
    #[error(
        "Value of size `{0}` cannot be converted to a PrimeField element. (The conversion for this type for smaller sized are supported though)"
    )]
    SizeNotSupported(String),
}

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("Value of type `{0}` cannot be converted to a PrimeField element.")]
    TypeNotSupported(String),
    #[error(
        "Value of size `{0}` cannot be converted to a PrimeField element. (The conversion for this type for smaller sized are supported though)"
    )]
    SizeNotSupported(String),
}

/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
pub enum DataTypeError {
    /// Data Type not supported error
    #[error("The provided data type {data_type} is not supported")]
    DataTypeNotSupported { data_type: DataType },

    /// Input numebr of variables error
    #[error("The provided input overflows the type {data_type}")]
    OverFlowError { data_type: DataType },

    /// Input numebr of variables error
    #[error("The provided input underflows the type {data_type}")]
    UnderFlowError { data_type: DataType },

    /// Input type error
    #[error("Expected an input of type {expected} but got {actual}")]
    InputTypeMismatch {
        expected: DataType,
        actual: DataType,
    },
}
